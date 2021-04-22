/*
 * Lightweight package to interpret End-of-Central-Directory (EOCD)
 * entries from a zip file. Supported standards: ZIP, ZIP64:
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 */

const fs = require("fs");
const path = require("path");


///////////////////////////////////////
const SZ_MB_4               = 4 * 1024 * 1024;
const SZ_MB_2               = 2 * 1024 * 1024;

const SIG_EOCD_64           = 0x06064b50;
const SIG_EOCD              = 0x06054b50;
const SIG_CDIR              = 0x02014b50;

const EXTSIG_ZIP64          = 0x0001;
const EXTSIG_AV             = 0x0007;
const EXTSIG_PFS            = 0x0008;
const EXTSIG_OS2            = 0x0009;
const EXTSIG_NTFS           = 0x000a;
const EXTSIG_OPENVMS        = 0x000c;
const EXTSIG_UNIX           = 0x000d;
const EXTSIG_STREAM         = 0x000e;
const EXTSIG_PATCH          = 0x000f;
const EXTSIG_X509_PKCS      = 0x0014;
const EXTSIG_X509_LOC       = 0x0015;
const EXTSIG_X509_CEN       = 0x0016;
const EXTSIG_CRYPT          = 0x0017;
const EXTSIG_RMC            = 0x0018;
const EXTSIG_CERT_LIST_PKCS = 0x0019;
const EXTSIG_TIMESTAMP      = 0x0020;
const EXTSIG_DECRYPT        = 0x0021;
const EXTSIG_SCRYPT_KEY     = 0x0022;
const EXTSIG_SCRYPT_DATA    = 0x0023;
const EXTSIG_IBM_UNCOMPRESS = 0x0065;
const EXTSIG_IBM_COMPRESS   = 0x0066;
const EXTSIG_POSZIP         = 0x4690;


const lget16 = (buf, off) => buf[off] | (buf[off+1] << 8);
const lget32 = (buf, off) => (lget16(buf, off) | (lget16(buf, off+2) << 16)) & 0xffffffff;
const lget64_bint = (buf, off) => BigInt(lget32(buf, off)) | (BigInt(lget32(buf, off+4)) << BigInt(32));

function arraycopy(src, srcPos, dest, destPos, len) {
  let srcTrunc = Math.max(0, src.length - srcPos);
  let destTrunc = Math.max(0, dest.length - destPos);
  let lim = Math.min(len, srcTrunc, destTrunc);
  for (let i=0; i<lim; i++) {
    dest[destPos+i] = src[srcPos+i];
  }
}

function uint8arr_to_str(uint8Arr) {
  return Buffer.from(uint8Arr).toString('utf-8');
}

function getbuf(size) {
  return new Uint8Array(size);
}

function cp_buf(buf, off, size) {
  let _buf = getbuf(size);
  arraycopy(buf, off, _buf, 0, _buf.length);
  return _buf;
}

function cp_buf_str(buf, off, size) {
  return uint8arr_to_str(cp_buf(buf, off, size));
}
///////////////////////////////////////


function randomAccessFile(filepath) {
  filepath = path.resolve(filepath);
  let fd = fs.openSync(filepath, 'r', 0o666);
  let {size: filesize} = fs.statSync(filepath);

  return {
    head: (buf, off, len) => {
      try {
        if (off > filesize || off < 0 || len < 0) {
          return -1;
        }

        len = Math.min(filesize, off+len) - off;
        return fs.readSync(fd, buf, 0, len, off);
      } catch (err) {
        return -1
      }
    },
    tail: (buf, off, len) => {
      try {
        if (off > filesize || off < 0 || len < 0) {
          return -1;
        }

        let end = filesize - off;
        off = Math.max(end - len, 0);
        len = end - off;
        return fs.readSync(fd, buf, 0, len, off);
      } catch (err) {
        return -1;
      }
    },
    close: () => {
      fs.closeSync(fd);
    }
  }
}

function consolidate_EOCD_ZIP64(eocd__64) {
  let eocd_64 = eocd__64, eocd = eocd__64;
  let isZip64 = false;
  return {
    isZip64,

    sig:                  isZip64 ? eocd_64.zip64_sig : eocd.sig,
    num_disk:             isZip64 ? eocd_64.zip64_num_disk : eocd.num_disk,
    num_disk_cd:          isZip64 ? eocd_64.zip64_num_disk_cd : eocd.num_disk_cd,
    num_disk_entries_cd:  isZip64 ? eocd_64.zip64_num_disk_entries_cd : eocd.num_disk_entries_cd,
    num_entries_cd:       isZip64 ? eocd_64.zip64_num_entries_cd : eocd.num_entries_cd,
    sz_cd:                isZip64 ? eocd_64.zip64_sz_cd : eocd.sz_cd,
    off_disk_cd:          isZip64 ? eocd_64.zip64_off_disk_cd : eocd.off_disk_cd,

    // zip only (no zip64)
    len_comment:          eocd.len_comment,
    comment:              eocd.comment,

    // zip64 only
    ver:                  eocd_64.ver,
    ver_ext:              eocd_64.ver_ext,
    ext:                  eocd_64.ext
  };
}

function EOCD(buf, off) {
  let eocd = {
    sig:                  lget32(buf, off),
    num_disk:             lget16(buf, off+4),
    num_disk_cd:          lget16(buf, off+6),
    num_disk_entries_cd:  lget16(buf, off+8),
    num_entries_cd:       lget16(buf, off+10),
    sz_cd:                lget32(buf, off+12),
    off_disk_cd:          lget32(buf, off+16),
    len_comment:          lget16(buf, off+20),
    comment:              null
  };

  let commentBuf = getbuf(eocd.len_comment);
  arraycopy(buf, off+22, commentBuf, 0, commentBuf.length);
  eocd.comment = uint8arr_to_str(commentBuf);

  return consolidate_EOCD_ZIP64(eocd);
}

function EOCD_64(buf, off, eocd) {
  let eocd_64 = {
    ...eocd,

    zip64_sig:                  lget32(buf, off),
    sz_eocd64:                  lget64_bint(buf, off+4),
    ver:                        lget16(buf, off+12),
    ver_ext:                    lget16(buf, off+14),
    zip64_num_disk:             lget32(buf, off+16),
    zip64_num_disk_cd:          lget32(buf, off+20),
    zip64_num_disk_entries_cd:  lget64_bint(buf, off+24),
    zip64_num_entries_cd:       lget64_bint(buf, off+32),
    zip64_sz_cd:                lget64_bint(buf, off+40),
    zip64_off_disk_cd:          lget64_bint(buf, off+48),
    zip64_ext:                  null
  };

  eocd_64.zip64_ext = cp_buf(buf, off+56, eocd_64.sz_eocd64 - 44 /* sizeof non-ext EOCD */);

  return consolidate_EOCD_ZIP64(eocd_64);
}

function CDIR(buf, off) {
  let cdir = {
    sig:            lget32(buf, off),
    ver:            lget16(buf, off+4),
    ver_ext:        lget16(buf, off+6),
    flg_gen:        lget16(buf, off+8),
    compression:    lget16(buf, off+10),
    tm_last_mod:    lget16(buf, off+12),
    dt_last_mod:    lget16(buf, off+14),
    crc_32:         lget32(buf, off+16),
    sz_compress:    lget32(buf, off+20),
    sz_uncompress:  lget32(buf, off+24),
    len_filename:   lget16(buf, off+28),
    len_ext:        lget16(buf, off+30),
    len_comment:    lget16(buf, off+34),
    num_disk:       lget16(buf, off+34),
    attrs_int:      lget16(buf, off+36),
    off_loc:        lget32(buf, off+38),

    // set below
    sz_cdir:        0,
    filename:       null,
    comment:        null
  };

  cdir.filename = cp_buf_str(buf, off+46, cdir.len_filename);
  cdir.comment = cp_buf_str(buf, off+46+cdir.len_filename+cdir.len_ext, cdir.len_comment);
  cdir.sz_cdir = 46 + cdir.len_filename + cdir.len_ext + cdir.len_comment

  if (cdir.len_ext > 0) {
    let ext_off = off+46+cdir.len_filename;
    let ext_len = cdir.len_ext + 4;

    let id_hdr, sz_data;
    let _ext_off = ext_off;
    const lim = ext_off + ext_len;
    while (_ext_off < lim) {
      id_hdr = lget16(buf, _ext_off);
      sz_data = lget16(buf, _ext_off+2);

      switch (id_hdr) {
        case EXTSIG_ZIP64:
          if (sz_data === 24 || sz_data === 28) {
            cdir = {
              ...cdir,

              sz_uncompress:  lget64_bint(buf, _ext_off+4),
              sz_compress:    lget64_bint(buf, _ext_off+12),
              off_loc:        lget64_bint(buf, _ext_off+20),
              num_disk:       sz_data === 28 ? lget64_bint(buf, off+28) : cdir.num_disk
            };
          }
          break;

        case EXTSIG_AV:
        case EXTSIG_PFS:
        case EXTSIG_OS2:
        case EXTSIG_NTFS:
        case EXTSIG_OPENVMS:
        case EXTSIG_UNIX:
        case EXTSIG_STREAM:
        case EXTSIG_PATCH:
        case EXTSIG_X509_PKCS:
        case EXTSIG_X509_LOC:
        case EXTSIG_X509_CEN:
        case EXTSIG_CRYPT:
        case EXTSIG_RMC:
        case EXTSIG_CERT_LIST_PKCS:
        case EXTSIG_TIMESTAMP:
        case EXTSIG_DECRYPT:
        case EXTSIG_SCRYPT_KEY:
        case EXTSIG_SCRYPT_DATA:
        case EXTSIG_IBM_UNCOMPRESS:
        case EXTSIG_IBM_COMPRESS:
        case EXTSIG_POSZIP:
        default:
      }
    }
  }

  return cdir;
}

function resizableBuffer() {
  let buf = new Uint8Array(0);

  const resize = (newLen, origOff, newOff, len) => {
    let tmp = new Uint8Array(newLen);
    let lenToCopy = len < 0 ? buf.length : Math.min(buf.length, len);

    if ((newLen - newOff + lenToCopy) > newLen) {
      lenToCopy = Math.max(newLen - newOff, 0);
    }

    arraycopy(buf, origOff, tmp, newOff, lenToCopy);
    buf = tmp;
  };

  return {
    coalesce_front: (_buf, off, len) => {
      if (len === 0) {
        return;
      }

      /*
       * (1) Resize buf to accommodate size of _buf
       * (2) Exactly copy contents of _buf into front of buf
       *     such that _buf and the old buf are concatenated
       *     without "empty" bytes in between
       */
      resize(buf.length + len, 0, len, -1);
      arraycopy(_buf, off, buf, 0, len);
    },
    resize,
    ensureSize: (size) => {
      if (buf.length <= size) {
        return;
      }

      resize(size, 0, 0, size);
    },
    getBuffer: () => buf,
    length: () => buf.byteLength,
    lget16: (off) => lget16(buf, off),
    lget32: (off) => lget32(buf, off)
  }
}

exports.eocd = (zipFile = '') => {
  let sb = randomAccessFile(zipFile);
  let rb = resizableBuffer();

  let eocd = null;

  let isFound = false;
  let buf_64 = getbuf(64);
  let offset = 0;
  let isZip64 = false;
  while (!isFound && offset < SZ_MB_4) {
    let len = sb.tail(buf_64, offset, buf_64.byteLength);
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
        isZip64 = eocd.isZip64;
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
  let buf_2mb = getbuf(SZ_MB_2);
  while (offset > cdStartOff) {
    let bytesLeft = offset - cdStartOff;
    let readsz = Math.min(bytesLeft, buf_2mb.byteLength);
    let len = sb.head(buf_2mb, offset-readsz, readsz);
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
          i += (cdir.sz_cdir - 1);
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

  sb.close();
  return {
    eocd,
    cdirList
  };
};
