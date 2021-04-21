/*
 * Lightweight package to interpret End-of-Central-Directory (EOCD)
 * entries from a zip file. Supported standards: ZIP, ZIP64:
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 */

const SZ_MB_4 = 4 * 1024 * 1024;
const SZ_MB_2 = 2 * 1024 * 1024;
const SIG_EOCD_64 = 0x06064b50;
const SIG_EOCD = 0x06054b50;
const SIG_CDIR = 0x02014b50;

function toRandomAccessBuffer(obj) {
  return {
    head: async (buf, off, len) => 0,
    tail: async (buf, off, len) => 0
  }
}

function consolidate_EOCD_ZIP64(eocd, eocd_64) {
  return {
    isZip64: () => false,
    sig: '',
    num_disk: '',
    num_disk_cd: '',
    num_disk_entries_cd: '',
    num_entries_cd: '',
    sz_cd: '',
    off_disk_cd: '',
    len_comment: '',
    comment: '',

    // zip64
    ver: '',
    ver_ext: ''
  };
}

function EOCD(buf, off) {
  return consolidate_EOCD_ZIP64({
  }, null);
}

function EOCD_64(buf, off, eocd) {
  return consolidate_EOCD_ZIP64(null, {

  });
}

function CDIR(buf, off) {
  return {
    size: () => 0,
    sig: '',
    ver: '',
    ver_ext: '',
    flg_gen: '',
    compression: '',
    tm_last_mod: '',
    dt_last_mod: '',
    crc_32: '',
    sz_compress: '',
    sz_uncompress: '',
    len_filename: '',
    len_ext: '',
    len_comment: '',
    num_disk: '',
    attrs_int: '',
    off_loc: '',
    filename: '',
    ext: {},
    comment: ''
  };
}

function resizableBuffer() {
  let buf = null;
  return {
    coalesce_front: (buf, off, len) => {},
    resize: (newLen, origOff, newOff, len) => {},
    ensureSize: (size) => {},
    getBuffer: () => buf,
    length: () => 0,
    lget16: (off) => 0,
    lget32: (off) => 0,
    lget64: (off) => 0
  }
}

// helper function to initialize buffer of size
function buf(size) {
  return new Uint8Array(size);
}

exports.eocd = async ({ zipFile = '' }) => {
  let sb = toRandomAccessBuffer(zipFile);
  let rb = resizableBuffer();

  let eocd = null;

  let isFound = false;
  let buf_64 = buf(64);
  let offset = 0;
  let isZip64 = false;
  while (!isFound && offset < SZ_MB_4) {
    let len = await sb.tail(buf_64, offset, buf_64.byteLength);
    offset += len;
    if (len === -1) {
      throw new Error("EOF");
    }

    rb.coalesce_front(buf_64, 0, len);
    /*
     * Back-to-Front traversal of buffer so to minimize
     * minimize potential signature collision with other
     * parts of zip file data.
     *
     *
     * Starts at the very back of the loop. Set loop
     * limit as the min(len+4, rb.length), where 'len'
     * is the number of bytes read in this pass.
     * rb.length is length of the entire buffer.
     *
     * The min() function ensures loop integrity on the
     * initial pass of the outer loop.
     *
     * Reason for len+4 is to check the last bytes of
     * the current stream against the first bytes of
     * the previous stream for EOCD signature. This is
     * patch work in case the signature is split in
     * the 4-byte window between consecutive streams.
     *
     * e.g.
     *
     * [0] [1] [2] [3] [4] | [5] [6] [7] [8] [9]
     *
     * let indices 0 to 4 be bytes from the
     * current stream, let indices 5 to 9 be bytes
     * from the previous stream.
     *
     * Then the signature could be in bytes from the
     * indicies:
     *   2 3 4 | 5
     *   3 4 | 5 6
     *   4 | 5 6 7
     *
     * Reason loop variable 'i' is initialized to lim-4
     * is so the loop always ends on an even iteration,
     * as the EOCD signature is 4 bytes.
     *
     * Note how i is decremented by 1 per loop: a
     * 2-byte sequence occurs in both even and odd
     * countings - we have to check for both.
     */
    let lim = Math.min(len+4, rb.length());
    for (let i=lim-4; i>=0; --i) {
      let bit32 = rb.lget32(i);
      if (isZip64) {
        if (bit32 === SIG_EOCD_64) {
          let newLen = rb.length() - i;
          rb.resize(newLen, i, 0, newLen);
          offset = rb.length();

          eocd = EOCD_64(rb.getBuffer(), 0, eocd);
          isFound = true;
          break;
        }
      } else if (bit32 === SIG_EOCD) {
        let newLen = rb.length() - i;
        rb.resize(newLen, i, 0, newLen);
        offset = rb.length();

        eocd = EOCD(rb.getBuffer(), 0);
        isZip64 = eocd.isZip64();
        if (!isZip64) {
          isFound = true;
        }

        break;
      }
    }

    // prevent out-of-memory
    rb.ensureSize(buf_64.byteLength);
  }

  if (!isFound || eocd === null) {
    throw new Error("EOCD Not Found");
  }

  if (eocd.num_disk !== 0 || eocd.num_disk_cd !== 0) {
    throw new Error("Multiple disks");
  }

  let cdirList = [];
  /*
   * Read all Central Directory Headers (ZIP/64)
   * (1) Locate start of Central Directory from EOCD
   *     off_disk_cd field
   * (2) Read backwards - from end of Central Directory
   *     to the beginning. Check bounds constantly
   *     to avoid EOF and spilling into file data
   *     section.
   * (3) For each CDIR discovered, read and add to
   *     list. After reading each CDIR, skip over
   *     read bytes to avoid signature collision.
   */
  const cdStartOff = eocd.off_disk_cd;
  const cdEndOff = eocd.off_disk_cd + eocd.sz_cd;
  offset = cdEndOff;
  let buf_2mb = buf(SZ_MB_2);
  while (offset > cdStartOff) {
    let bytesLeft = offset - cdStartOff;
    let readsz = Math.min(bytesLeft, buf_2mb.byteLength);
    let len = await sb.head(buf_2mb, offset-readsz, readsz);
    offset -= len;
    if (len === -1) {
      throw new Error("EOF")
    }

    rb.coalesce_front(buf_2mb, 0, len);
    let lim = Math.min(len+4, rb.length());
    for (let i=0; (i+4)<lim; ++i) {
      let bit32 = rb.lget32(i);
      if (bit32 === SIG_CDIR) {
        try {
          let cdir = CDIR(rb.getBuffer(), i);
          cdirList.unshift(cdir);

          // Skip over read bytes, "-1" accounts for loop increment
          i += (cdir.size() - 1);
        } catch (err) {
          // swallow
          console.error(err);
        }
      }
    }

    /*
     * Ensures buffer does not exceed a size of
     * 2 * buffer.length. This prevents out-of
     * -memory, while ensuring our patch-up logic
     * between different reads (see above comments)
     * is accounted for.
     */
    rb.ensureSize(buf_2mb.byteLength);
  }

  // final sanity check
  let expected = eocd.num_entries_cd;
  let actual = cdirList.length;
  if (expected !== actual) {
    throw new Error(`Expected ${expected} CDIR records, got ${actual}`);
  }

  return {
    eocd,
    cdirList
  };
};
