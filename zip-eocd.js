/*
 * Lightweight package to interpret End-of-Central-Directory (EOCD)
 * entries from a zip file. Supported standards: ZIP, ZIP64:
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 */

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const CRC32 = require("crc-32");


///////////////////////////////////////
const SZ_MB_4               = 4 * 1024 * 1024;
const SZ_MB_2               = 2 * 1024 * 1024;
const SZ_LOC_MAX            = 1024;

const SIG_EOCD_64           = 0x06064b50;
const SIG_EOCD              = 0x06054b50;
const SIG_CDIR              = 0x02014b50;
const SIG_LOC               = 0x04034b50;

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

const C_DEFLATE           = 8;
const C_STORE             = 0;
const C_SHRUNK            = 1;
const C_REDUCED_CFACTOR_1 = 2;
const C_REDUCED_CFACTOR_2 = 3;
const C_REDUCED_CFACTOR_3 = 4;
const C_REDUCED_CFACTOR_4 = 5;
const C_IMPLODED          = 6;
const C_DEFLATE_64        = 9;
const C_BZIP2             = 12;
const C_LZMA              = 14;
const C_IBM_TERSE         = 18;
const C_IBM_LZ77_z        = 19;
const C_ZSTD              = 93;
const C_MP3               = 94;
const C_XZ                = 95;
const C_JPEG              = 96;
const C_WAVPACK           = 97;
const C_PPMD_v1           = 98;
const C_AE_X              = 99;


const lget16 = (buf, off) => buf[off] | (buf[off+1] << 8);
const lget32 = (buf, off) => (lget16(buf, off) | (lget16(buf, off+2) << 16)) & 0xffffffff;

const lget16_bint = (buf, off) => BigInt(buf[off]) | (BigInt(buf[off+1]) << 8n);
const lget32_bint = (buf, off) => (lget16_bint(buf, off) | (lget16_bint(buf, off+2) << 16n)) & 0xffffffffn;
const lget64_bint = (buf, off) => lget32_bint(buf, off) | (lget32_bint(buf, off+4) << 32n);
const num32b = (bigint) => Number(bigint);
const bint = (num) => BigInt(num);
const BInt_max = (...entries) => {
  if (entries.length === 0) {
    return NaN;
  }

  let max = entries[0];
  for (let entry of entries) {
    if (entry > max) {
      max = entry;
    }
  }

  return max;
}

const BInt_min = (...entries) => {
  if (entries.length === 0) {
    return NaN;
  }

  let min = entries[0];
  for (let entry of entries) {
    if (entry < min) {
      min = entry;
    }
  }

  return min;
}

function arraycopy(src, srcPos, dest, destPos, len) {
  let srcTrunc = Math.max(0, src.length - srcPos);
  let destTrunc = Math.max(0, dest.length - destPos);
  let lim = Math.min(len, srcTrunc, destTrunc);
  for (let i=0; i<lim; i++) {
    dest[destPos+i] = src[srcPos+i];
  }
}

function assert_crc32(buf, expected_crc32) {
  let crc32 = CRC32.buf(buf);
  if (crc32 !== expected_crc32) {
    throw new Error(`CRC-32: Checksum mismatch. Expected: ${expected_crc32}, Actual: ${crc32}`);
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
      off = Number(off);
      if (!Number.isSafeInteger(off)) {
        throw new Error('offset is too big!');
      }

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

function ZIP64_ext(buf, off, ext_len) {
  let zip64_ext = {};

  let id_hdr, sz_data;
  let _ext_off = off;
  const lim = off + ext_len;
  while (_ext_off < lim) {
    id_hdr = lget16(buf, _ext_off);
    sz_data = lget16(buf, _ext_off+2);

    switch (id_hdr) {
      case EXTSIG_ZIP64:
        if (sz_data === 24 || sz_data === 28) {
          zip64_ext = {
            ...zip64_ext,

            sz_uncompress:  lget64_bint(buf, _ext_off+4),
            sz_compress:    lget64_bint(buf, _ext_off+12),
            off_loc:        lget64_bint(buf, _ext_off+20),
          };

          if (sz_data === 28) {
            zip64_ext.num_disk = lget64_bint(buf, off+28);
          }
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

    _ext_off += (4 + sz_data);
  }

  return zip64_ext;
}

function LOC(buf, off) {
  let loc = {
    sig:            lget32(buf, off),
    ver:            lget16(buf, off+4),
    flg_gen:        lget16(buf, off+6),
    compression:    lget16(buf, off+8),
    tm_last_mod:    lget16(buf, off+10),
    dt_last_mod:    lget16(buf, off+12),
    crc_32:         lget32(buf, off+14),
    sz_compress:    lget32_bint(buf, off+18),
    sz_uncompress:  lget32_bint(buf, off+22),
    len_filename:   lget16(buf, off+26),
    len_ext:        lget16(buf, off+28),

    // set below
    filename: '',
    sz_loc: 0
  };

  loc.filename = cp_buf_str(buf, off+30, loc.len_filename);
  loc.sz_loc = 30 + loc.len_filename + loc.len_ext;

  if (loc.len_ext > 0) {
    loc = {
      ...loc,
      ...ZIP64_ext(buf, off+46+loc.len_filename, loc.len_ext + 4)
    };
  }

  return loc;
}

function EOCD(buf, off) {
  let eocd = {
    sig:                  lget32(buf, off),
    num_disk:             lget16(buf, off+4),
    num_disk_cd:          lget16(buf, off+6),
    num_disk_entries_cd:  lget16(buf, off+8),
    num_entries_cd:       lget16(buf, off+10),
    sz_cd:                lget32_bint(buf, off+12),
    off_disk_cd:          lget32_bint(buf, off+16),
    len_comment:          lget16(buf, off+20),

    // set below
    comment:              null,
    is_zip_64:            false
  };

  eocd.comment = cp_buf_str(buf, off+22, eocd.len_comment);
  eocd.is_zip_64 = eocd.num_disk === 0xffff
    || eocd.num_disk_cd === 0xffff
    || eocd.num_disk_entries_cd === 0xffff
    || eocd.sz_cd === 0xffffffffn
    || eocd.off_disk_cd === 0xffffffffn;

  return eocd;
}

function EOCD_64(buf, off, eocd) {
  let eocd_64 = {
    ...eocd,

    zip64_sig:            lget32(buf, off),
    sz_eocd64:            lget64_bint(buf, off+4),

    // zip64 only
    ver:                  lget16(buf, off+12),
    ver_ext:              lget16(buf, off+14),

    // merge with zip eocd
    num_disk:             lget32_bint(buf, off+16),
    num_disk_cd:          lget32_bint(buf, off+20),
    num_disk_entries_cd:  lget64_bint(buf, off+24),
    num_entries_cd:       lget64_bint(buf, off+32),
    sz_cd:                lget64_bint(buf, off+40),
    off_disk_cd:          lget64_bint(buf, off+48),

    // zip6 only
    zip64_ext:            null
  };

  if (eocd_64.sz_eocd64 < bint(Number.MAX_SAFE_INTEGER)) {
    // 44 = sizeof non-ext EOCD
    eocd_64.zip64_ext = cp_buf(buf, off+56, num32b(eocd_64.sz_eocd64) - 44);
  } else {
    eocd_64.zip64_ext = 'EOCD_64 EXT TOO LARGE';
  }

  return eocd_64;
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
    sz_compress:    lget32_bint(buf, off+20),
    sz_uncompress:  lget32_bint(buf, off+24),
    len_filename:   lget16(buf, off+28),
    len_ext:        lget16(buf, off+30),
    len_comment:    lget16(buf, off+32),
    num_disk:       lget16(buf, off+34),
    attrs_int:      lget16(buf, off+36),
    attrs_ext:      lget32_bint(buf, off+38),
    off_loc:        lget32_bint(buf, off+42),

    // set below
    sz_cdir:        0,
    filename:       null,
    comment:        null
  };

  cdir.filename = cp_buf_str(buf, off+46, cdir.len_filename);
  cdir.comment = cp_buf_str(buf, off+46+cdir.len_filename+cdir.len_ext, cdir.len_comment);
  cdir.sz_cdir = 46 + cdir.len_filename + cdir.len_ext + cdir.len_comment

  if (cdir.len_ext > 0) {
    cdir = {
      ...cdir,
      ...ZIP64_ext(buf, off+46+cdir.len_filename, cdir.len_ext + 4)
    };
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

function readentry(sb, cdir) {
  /*
   * 1) Read Local Header + Data
   * 2) Parse Local Header
   * 3) Isolate Data section of ZIP entry
   * 4) Extract ZIP entry - depends on compression algorithm
   *      - STORE: return data section
   *      - DEFLATE: use zlib
   *      - ...other: <not supported>
   */

  // 1)
  let buf_entry = getbuf(SZ_LOC_MAX + num32b(cdir.sz_compress));
  let len = sb.head(buf_entry, cdir.off_loc, buf_entry.byteLength);
  if (len === -1) {
    throw new Error('Could not read entry');
  }

  // 2)
  let loc = LOC(buf_entry, 0);
  if (loc.sig !== SIG_LOC) {
    throw new Error('invalid local header signature');
  }

  // 3)
  let buf_data = buf_entry.subarray(
    loc.sz_loc,
    loc.sz_loc + num32b(loc.sz_compress));

  // 4)
  switch (cdir.compression) {
    case C_STORE:
    {
      assert_crc32(buf_data, loc.crc_32);
      return buf_data;
    }

    case C_DEFLATE:
    {
      let buf_inflate = zlib.inflateRawSync(buf_data);
      assert_crc32(buf_inflate, loc.crc_32);
      return buf_inflate;
    }

    case C_SHRUNK:
    case C_REDUCED_CFACTOR_1:
    case C_REDUCED_CFACTOR_2:
    case C_REDUCED_CFACTOR_3:
    case C_REDUCED_CFACTOR_4:
    case C_IMPLODED:
    case C_DEFLATE_64:
    case C_BZIP2:
    case C_LZMA:
    case C_IBM_TERSE:
    case C_IBM_LZ77_z:
    case C_ZSTD:
    case C_MP3:
    case C_XZ:
    case C_JPEG:
    case C_WAVPACK:
    case C_PPMD_v1:
    case C_AE_X:
    default:
      throw new Error('Invalid compression method');
  }
}

/**
 * @returns Returns the following object:
 *  {
 *    eocd: {
 *      sig,
 *      num_disk,
 *      num_disk_cd,
 *      num_disk_entries_cd,
 *      num_entries_cd,
 *      sz_cd,
 *      off_disk_cd,
 *      len_comment,
 *      comment,
 *    },
 *    cdirList: [{
 *      sig,
 *      ver,
 *      ver_ext,
 *      flg_gen,
 *      compression,
 *      tm_last_mod,
 *      dt_last_mod,
 *      crc_32,
 *      sz_compress,
 *      sz_uncompress,
 *      len_filename,
 *      len_ext,
 *      len_comment,
 *      num_disk,
 *      attrs_int,
 *      attrs_ext,
 *      off_loc,
 *      sz_cdir,
 *      filename,
 *      comment
 *    }]
 *  }
 */
exports.zipEOCD = (zipFile = '') => {
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
        isZip64 = eocd.is_zip_64;
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
    let readsz = num32b(BInt_min(bytesLeft, bint(buf_2mb.byteLength)));
    let head_offset = num32b(offset - bint(readsz));
    let len = sb.head(buf_2mb, head_offset, readsz);

    offset -= bint(len);
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
  let expected = bint(eocd.num_entries_cd);
  let actual = bint(cdirList.length);
  if (expected !== actual) {
    throw new Error(`Expected ${expected} CDIR records, got ${actual}`);
  }

  return {
    eocd,
    cdirList,
    unzip: (cdir) => readentry(sb, cdir),
    close: () => {
      sb.close();
    }
  };
};
