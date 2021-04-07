#include "k-chkfs.hh"
#include "k-ahci.hh"
#include "k-chkfsiter.hh"

bufcache bufcache::bc;
wait_queue diskq;
list<bcentry, &bcentry::links_> dirty_list;
spinlock dirty_lock;

bufcache::bufcache() {
}


// bufcache::get_disk_entry(bn, cleaner)
//    Reads disk block `bn` into the buffer cache, obtains a reference to it,
//    and returns a pointer to its bcentry. The returned bcentry has
//    `buf_ != nullptr` and `estate_ >= es_clean`. The function may block.
//
//    If this function reads the disk block from disk, and `cleaner != nullptr`,
//    then `cleaner` is called on the entry to clean the block data.
//
//    Returns `nullptr` if there's no room for the block.

bcentry* bufcache::get_disk_entry(chkfs::blocknum_t bn,
                                  bcentry_clean_function cleaner, bool noblock) {
    assert(chkfs::blocksize == PAGESIZE);
    auto irqs = lock_.lock();

    // look for slot containing `bn`
    size_t i, empty_slot = -1;
    // LRU eviction policy
    size_t evict = -1,
        evict_dirty = -1;
    unsigned long lru_time = -1,
        lru_dirty_time = -1;
    for (i = 0; i != ne; ++i) {
        if (e_[i].empty()) {
            if (empty_slot == size_t(-1)) {
                empty_slot = i;
            }
        } else {
            if (e_[i].bn_ == bn) {
                break;
            } else if (e_[i].ref_ == 0 && e_[i].bn_ != 0 && e_[i].bn_ != 1) {
                if (e_[i].estate_ != bcentry::es_dirty) {
                    if (evict == size_t(-1)) {
                        evict = i;
                        lru_time = e_[i].ref_time_;
                    } else if (e_[i].ref_time_ < lru_time) {
                        lru_time = e_[i].ref_time_;
                        evict = i;
                    }
                } else {
                    // dirty state
                    if (evict_dirty == size_t(-1)) {
                        evict_dirty = i;
                        lru_dirty_time = e_[i].ref_time_;
                    } else if (e_[i].ref_time_ < lru_dirty_time) {
                        lru_dirty_time = e_[i].ref_time_;
                        evict_dirty = i;
                    }
                }
            }
        }
    }

    if (i == ne) {
        // fine, get a free slot
        if (empty_slot == size_t(-1) && evict != size_t(-1)) {
            // evict :D
            empty_slot = evict;
            e_[evict].lock_.lock_noirq();
            e_[evict].estate_ = bcentry::es_empty;
            e_[evict].lock_.unlock_noirq();
        } else if (empty_slot == size_t(-1) && evict_dirty != size_t(-1) && !noblock) {
            e_[evict_dirty].get_write();
            lock_.unlock(irqs); 

            sata_disk->write(e_[evict_dirty].buf_, chkfs::blocksize, chkfs::blocksize*e_[evict_dirty].bn_, nullptr);
            irqs = lock_.lock();
            {
                spinlock_guard guard(e_[evict_dirty].lock_);
                e_[evict_dirty].estate_ = bcentry::es_empty;
            
                if(e_[evict_dirty].links_.is_linked()){
                    spinlock_guard dirty_guard(dirty_lock);
                    dirty_list.erase(&e_[evict_dirty]);
                }
            }
            e_[evict_dirty].put_write();
            empty_slot = evict_dirty;
        }
        i = empty_slot;
    }

    if (i == ne) { // still
        return nullptr;
    }

    // obtain entry lock
    e_[i].lock_.lock_noirq();

    // mark allocated if empty
    if (e_[i].empty()) {
        e_[i].estate_ = bcentry::es_allocated;
        e_[i].bn_ = bn;
    }

    // no longer need cache lock
    lock_.unlock_noirq();

    // mark reference
    if (!noblock) {
        e_[i].ref_++;
    }

    // load block
    bool ok = e_[i].load(irqs, cleaner, noblock);

    // unlock and return entry
    if (!ok && !noblock) {
        e_[i].ref_--;
    }
    e_[i].ref_time_ = ticks.load();
    e_[i].lock_.unlock(irqs);
    return ok ? &e_[i] : nullptr;
}


// bcentry::load(irqs, cleaner)
//    Completes the loading process for a block. Requires that `lock_` is
//    locked, that `estate_ >= es_allocated`, and that `bn_` is set to the
//    desired block number.

bool bcentry::load(irqstate& irqs, bcentry_clean_function cleaner, bool noblock) {
    bufcache& bc = bufcache::get();

    // load block, or wait for concurrent reader to load it
    while (true) {
        assert(estate_ != es_empty);
        switch (estate_) {
        case es_allocated:
            if (!buf_) {
                buf_ = reinterpret_cast<unsigned char*>
                    (kalloc(chkfs::blocksize));
                if (!buf_) {
                    return false;
                }
            }
            if (noblock) {
                lock_.unlock(irqs);
                int r = sata_disk->read(buf_, chkfs::blocksize, bn_ * chkfs::blocksize, &fetch_status_);
                estate_ = r < 0 ? es_allocated : es_prefetch;
                irqs = lock_.lock();
                return r >= 0;
            } else {
                estate_ = es_loading;
                lock_.unlock(irqs);
                sata_disk->read(buf_, chkfs::blocksize, bn_ * chkfs::blocksize, nullptr);
                irqs = lock_.lock();
                estate_ = es_clean;
                if (cleaner) {
                    cleaner(this);
                }
                bc.read_wq_.wake_all();
            }
            break;
        case es_loading:
            waiter().block_until(bc.read_wq_, [&] () {
                return estate_ != es_loading;
            }, lock_, irqs);
            break;
        case es_prefetch:
            waiter().block_until(sata_disk->wq_, [&] () {
                    return fetch_status_ != E_AGAIN;
                }, lock_, irqs);
            estate_ = es_clean;
            if (cleaner) {
                cleaner(this);
            }
            bc.read_wq_.wake_all();
            break;
        default:
            return true;
        }
    }
}


// bcentry::put()
//    Releases a reference to this buffer cache entry. The caller must
//    not use the entry after this call.

void bcentry::put() {
    spinlock_guard guard(lock_);
    assert(ref_ != 0);
    ref_--;
}


// bcentry::get_write()
//    Obtains a write reference for this entry.

void bcentry::get_write() {
    if (write_ref_) {
        // wait until no more write references
        w_.block_until(diskq, [&] () {
            return !write_ref_;
        });
    }
    spinlock_guard guard(lock_);
    ++write_ref_;
    estate_ = es_dirty;
    if (!links_.is_linked()) {
        spinlock_guard dirty_guard(dirty_lock);
        dirty_list.push_back(this);
    }
}


// bcentry::put_write()
//    Releases a write reference for this entry.

void bcentry::put_write() {
    {
        spinlock_guard guard(lock_);
        write_ref_--;
    }
    diskq.wake_all();
}


// bufcache::sync(drop)
//    Writes all dirty buffers to disk, blocking until complete.
//    If `drop > 0`, then additionally free all buffer cache contents,
//    except referenced blocks. If `drop > 1`, then assert that all inode
//    and data blocks are unreferenced.

int bufcache::sync(int drop) {
    // write dirty buffers to disk

    list<bcentry, &bcentry::links_> dirty;
    // take responsibility for these buffers
    dirty.swap(dirty_list);
    while (bcentry* e = dirty.pop_front()) {
        if (!e->buf_) {
            continue;
        }

        e->get_write();
        sata_disk->write(e->buf_, chkfs::blocksize, chkfs::blocksize * e->bn_, nullptr);
        {
            spinlock_guard guard(e->lock_);
            e->estate_ = e->es_clean;
        }
        e->put_write();
        if (!e->ref_) {
            e->clear();
        }
    } 

    // drop clean buffers if requested
    if (drop > 0) {
        spinlock_guard guard(lock_);
        for (size_t i = 0; i != ne; ++i) {
            spinlock_guard eguard(e_[i].lock_);

            // validity checks: referenced entries aren't empty; if drop > 1,
            // no data blocks are referenced
            assert(e_[i].ref_ == 0 || e_[i].estate_ != bcentry::es_empty);
            if (e_[i].ref_ > 0 && drop > 1 && e_[i].bn_ >= 2) {
                error_printf(CPOS(22, 0), COLOR_ERROR, "sync(2): block %u has nonzero reference count\n", e_[i].bn_);
                assert_fail(__FILE__, __LINE__, "e_[i].bn_ < 2");
            }

            // actually drop buffer
            if (e_[i].ref_ == 0) {
                e_[i].clear();
            }
        }
    }

    return 0;
}


// inode lock functions
//    The inode lock protects the inode's size and data references.
//    It is a read/write lock; multiple readers can hold the lock
//    simultaneously.
//
//    IMPORTANT INVARIANT: If a kernel task has an inode lock, it
//    must also hold a reference to the disk page containing that
//    inode.

namespace chkfs {

void inode::lock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    while (true) {
        if (v >= mlock_t(-2)) {
            current()->yield();
            v = mlock.load(std::memory_order_relaxed);
        } else if (mlock.compare_exchange_weak(v, v + 1,
                                               std::memory_order_acquire)) {
            return;
        } else {
            // `compare_exchange_weak` already reloaded `v`
            pause();
        }
    }
}

void inode::unlock_read() {
    mlock_t v = mlock.load(std::memory_order_relaxed);
    assert(v != 0 && v != mlock_t(-1));
    while (!mlock.compare_exchange_weak(v, v - 1,
                                        std::memory_order_release)) {
        pause();
    }
}

void inode::lock_write() {
    mlock_t v = 0;
    while (!mlock.compare_exchange_weak(v, mlock_t(-1),
                                        std::memory_order_acquire)) {
        current()->yield();
        v = 0;
    }
}

void inode::unlock_write() {
    assert(has_write_lock());
    mlock.store(0, std::memory_order_release);
}

bool inode::has_write_lock() const {
    return mlock.load(std::memory_order_relaxed) == mlock_t(-1);
}

}


// chickadeefs state

chkfsstate chkfsstate::fs;

chkfsstate::chkfsstate() {
}


// clean_inode_block(entry)
//    Called when loading an inode block into the buffer cache. It clears
//    values that are only used in memory.

static void clean_inode_block(bcentry* entry) {
    uint32_t entry_index = entry->index();
    auto is = reinterpret_cast<chkfs::inode*>(entry->buf_);
    for (unsigned i = 0; i != chkfs::inodesperblock; ++i) {
        // inode is initially unlocked
        is[i].mlock = 0;
        // containing entry's buffer cache position is `entry_index`
        is[i].mbcindex = entry_index;
    }
}


// chkfsstate::get_inode(inum)
//    Returns inode number `inum`, or `nullptr` if there's no such inode.
//    Obtains a reference on the buffer cache block containing the inode;
//    you should eventually release this reference by calling `ino->put()`.

chkfs::inode* chkfsstate::get_inode(inum_t inum) {
    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    chkfs::inode* ino = nullptr;
    if (inum > 0 && inum < sb.ninodes) {
        auto bn = sb.inode_bn + inum / chkfs::inodesperblock;
        if (auto inode_entry = bc.get_disk_entry(bn, clean_inode_block)) {
            ino = reinterpret_cast<inode*>(inode_entry->buf_);
        }
    }
    if (ino != nullptr) {
        ino += inum % chkfs::inodesperblock;
    }
    return ino;
}


namespace chkfs {
// chkfs::inode::entry()
//    Returns a pointer to the buffer cache entry containing this inode.
//    Requires that this inode is a pointer into buffer cache data.
bcentry* inode::entry() {
    assert(mbcindex < bufcache::ne);
    auto entry = &bufcache::get().e_[mbcindex];
    assert(entry->contains(this));
    return entry;
}

// chkfs::inode::put()
//    Releases the caller’s reference to this inode, which must be located
//    in the buffer cache.
void inode::put() {
    entry()->put();
}
}

void chkfsstate::prefetch(inode* inode, off_t off){
    // Prefetch next block
    chkfs_fileiter it(inode);
    blocknum_t bn = it.find(off).blocknum();
    bufcache& bc = bufcache::get();
    bc.get_disk_entry(bn, nullptr, true);
}


// chkfsstate::lookup_inode(dirino, filename)
//    Looks up `filename` in the directory inode `dirino`, returning the
//    corresponding inode (or nullptr if not found). The caller must have
//    a read lock on `dirino`. The returned inode has a reference that
//    the caller should eventually release with `ino->put()`.

chkfs::inode* chkfsstate::lookup_inode(inode* dirino,
                                       const char* filename) {
    chkfs_fileiter it(dirino);

    // read directory to find file inode
    chkfs::inum_t in = 0;
    for (size_t diroff = 0; !in; diroff += blocksize) {
        if (bcentry* e = it.find(diroff).get_disk_entry()) {
            size_t bsz = min(dirino->size - diroff, blocksize);
            auto dirent = reinterpret_cast<chkfs::dirent*>(e->buf_);
            for (unsigned i = 0; i * sizeof(*dirent) < bsz; ++i, ++dirent) {
                if (dirent->inum && strcmp(dirent->name, filename) == 0) {
                    in = dirent->inum;
                    break;
                }
            }
            e->put();
        } else {
            return nullptr;
        }
    }
    return get_inode(in);
}


// chkfsstate::lookup_inode(filename)
//    Looks up `filename` in the root directory.

chkfs::inode* chkfsstate::lookup_inode(const char* filename) {
    auto dirino = get_inode(1);
    if (dirino) {
        dirino->lock_read();
        auto ino = fs.lookup_inode(dirino, filename);
        dirino->unlock_read();
        dirino->put();
        return ino;
    } else {
        return nullptr;
    }
}


// chkfsstate::allocate_extent(unsigned count)
//    Allocates and returns the first block number of a fresh extent.
//    The returned extent doesn't need to be initialized (but it should not be
//    in flight to the disk or part of any incomplete journal transaction).
//    Returns the block number of the first block in the extent, or an error
//    code on failure. Errors can be distinguished by
//    `blocknum >= blocknum_t(E_MINERROR)`.

auto chkfsstate::allocate_extent(unsigned count) -> blocknum_t {
    bufcache& bc = bufcache::get();
    bcentry* superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    chkfs::superblock& sb = *reinterpret_cast<chkfs::superblock*>(superblock_entry->buf_ + chkfs::superblock_offset);
    superblock_entry->put();
    chkfs::blocknum_t bn =  sb.fbb_bn;
    bcentry* fbb = bc.get_disk_entry(bn);
    if (!fbb) {
        return E_NOENT;
    }
    fbb->get_write();
    bitset_view bitmap = bitset_view((uint64_t*) fbb->buf_, (size_t) chkfs::blocksize << 3);
    blocknum_t start_extent = bitmap.find_lsb(0);
    bitmap[start_extent] = 0;
    fbb->put_write();
    fbb->put();
    return start_extent;
}
