// In-browser metadata inspection and pixel re-encoding.
// Nothing here talks to the network: the original file never leaves the page.
import { CATEGORY_ORDER, riskOf } from './categories.js';

const latin1 = new TextDecoder('latin1');
const utf8 = new TextDecoder('utf-8', { fatal: false });
const utf16be = new TextDecoder('utf-16be');
const utf16le = new TextDecoder('utf-16le');

const AI_SIGNATURES = [
  ['Stable Diffusion', /Steps:\s*\d+[\s\S]{0,400}Sampler:|Model hash:|sd_model|stable[- ]?diffusion|automatic1111|\bA1111\b|InvokeAI|Fooocus|sd-metadata/i],
  ['ComfyUI', /"class_type"\s*:|ComfyUI/],
  ['Midjourney', /midjourney|\bJob ID:\s*[0-9a-f-]{8,}/i],
  ['ChatGPT / DALL·E', /openai|chatgpt|dall[·\-\s]?e|gpt-?4o|gpt[- ]?image/i],
  ['Sora', /\bsora\b/i],
  ['Google Gemini', /gemini|imagen|nano[- ]?banana|made with google ai|synthid/i],
  ['Adobe Firefly', /firefly/i],
  ['Kling', /\bkling\b|kuaishou/i],
  ['Runway', /runwayml|\brunway\b/i],
  ['Pika', /pika ?labs|\bpika\b/i],
  ['Flux', /\bflux(\.1)?[- ]?(dev|schnell|pro|kontext)\b|black forest labs/i],
  ['NovelAI', /novelai/i],
  ['Leonardo', /leonardo\.ai/i],
  ['Ideogram', /ideogram/i],
  ['Microsoft Designer', /bing image creator|microsoft designer/i],
  ['AIGC label', /"?AIGC"?\s*[:=]|ContentProducer|ProduceID|ContentPropagator/],
  ['AI-generated flag', /trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|algorithmicMedia/i],
];

const MAX_VALUE = 1000;
export const VIDEO_FORMATS = new Set(['mp4', 'mov']);
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const round = (n, d = 1) => (Number.isFinite(n) ? String(+n.toFixed(d)) : '');
const clean = (s) => String(s ?? '').replace(/\0+/g, ' ').replace(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g, '').trim();

function indexOf(bytes, ascii, from = 0, to = bytes.length) {
  const needle = Array.from(ascii, (c) => c.charCodeAt(0));
  outer: for (let i = from; i <= to - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function startsWith(bytes, ascii, at = 0) {
  return indexOf(bytes, ascii, at, at + ascii.length) === at;
}

async function inflate(bytes) {
  try {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return new Uint8Array();
  }
}

// Collects container blocks (what gets cut out) and individual fields (what they said).
class Report {
  constructor() {
    this.blocks = [];
    this.fields = [];
    this.text = '';
    this.gps = null;
    this.thumbnails = [];
    this.seen = new Map();
  }

  block(kind, label, bytes, rawText = '') {
    this.blocks.push({ kind, label, bytes });
    if (rawText) this.text += '\n' + rawText;
  }

  field(cat, name, value, src) {
    value = clean(Array.isArray(value) ? value.join(', ') : value);
    if (!value) return;
    if (value.length > MAX_VALUE) value = value.slice(0, MAX_VALUE) + '…';
    const key = `${cat}|${name}|${value}`.toLowerCase();
    const prev = this.seen.get(key);
    if (prev) {
      if (!prev.src.split(', ').includes(src)) prev.src += `, ${src}`;
      return;
    }
    const f = { cat, name, value, src };
    this.seen.set(key, f);
    this.fields.push(f);
    this.text += '\n' + value;
  }
}

// --- TIFF / EXIF ------------------------------------------------------------
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4 };

function tiffReader(tiff) {
  const view = new DataView(tiff.buffer, tiff.byteOffset, tiff.byteLength);
  const order = view.byteLength >= 8 ? view.getUint16(0) : 0;
  if (order !== 0x4949 && order !== 0x4d4d) return null;
  const le = order === 0x4949;
  const u16 = (o) => view.getUint16(o, le);
  const u32 = (o) => view.getUint32(o, le);
  const i32 = (o) => view.getInt32(o, le);

  const value = (type, count, at) => {
    const size = (TYPE_SIZE[type] || 1) * count;
    const off = size <= 4 ? at : u32(at);
    if (count > 1e7 || off + size > view.byteLength) return null;
    const list = (step, read) => Array.from({ length: Math.min(count, 256) }, (_, i) => read(off + i * step));
    switch (type) {
      case 2: return utf8.decode(tiff.subarray(off, off + count)).replace(/\0[\s\S]*$/, '').trim();
      case 1: case 6: case 7: return tiff.subarray(off, off + count);
      case 3: return list(2, u16);
      case 4: case 13: return list(4, u32);
      case 9: return list(4, i32);
      case 5: return list(8, (o) => u32(o) / (u32(o + 4) || 1));
      case 10: return list(8, (o) => i32(o) / (i32(o + 4) || 1));
      default: return null;
    }
  };

  // Returns tag -> value plus the offset of the next IFD in the chain.
  const ifd = (off) => {
    const tags = new Map();
    if (!off || off + 2 > view.byteLength) return { tags, next: 0 };
    const n = u16(off);
    for (let i = 0; i < n && off + 2 + i * 12 + 12 <= view.byteLength; i++) {
      const e = off + 2 + i * 12;
      try { tags.set(u16(e), value(u16(e + 2), u32(e + 4), e + 8)); } catch { /* malformed entry: skip */ }
    }
    const nextAt = off + 2 + n * 12;
    return { tags, next: nextAt + 4 <= view.byteLength ? u32(nextAt) : 0 };
  };

  return { ifd, first: u32(4), le };
}

const ENUM = {
  orientation: { 1: 'Normal', 2: 'Mirrored', 3: 'Rotated 180°', 4: 'Flipped vertically', 5: 'Mirrored + rotated 90° CCW', 6: 'Rotated 90° CW', 7: 'Mirrored + rotated 90° CW', 8: 'Rotated 90° CCW' },
  program: ['Not defined', 'Manual', 'Program auto', 'Aperture priority', 'Shutter priority', 'Creative', 'Action', 'Portrait', 'Landscape'],
  metering: { 0: 'Unknown', 1: 'Average', 2: 'Centre-weighted', 3: 'Spot', 4: 'Multi-spot', 5: 'Matrix', 6: 'Partial', 255: 'Other' },
  exposureMode: ['Auto', 'Manual', 'Auto bracket'],
  whiteBalance: ['Auto', 'Manual'],
  scene: ['Standard', 'Landscape', 'Portrait', 'Night'],
};

const text = (v) => (typeof v === 'string' ? v : v instanceof Uint8Array ? utf8.decode(v) : Array.isArray(v) ? v.join(', ') : '');
const ucs2 = (v) => (v instanceof Uint8Array ? utf16le.decode(v) : text(v));
const first = (fn) => (v) => (Array.isArray(v) && v.length ? fn(v[0]) : text(v));

function userComment(v, le) {
  if (!(v instanceof Uint8Array)) return text(v);
  const head = latin1.decode(v.subarray(0, 8));
  const body = v.subarray(8);
  if (head.startsWith('UNICODE')) return (le ? utf16le : utf16be).decode(body);
  return utf8.decode(head.startsWith('ASCII') || head === '\0\0\0\0\0\0\0\0' ? body : v);
}

// tag: [name, category, formatter]
const EXIF_TAGS = {
  0x000b: ['Processing software', 'software'],
  0x010e: ['Description', 'description'],
  0x010f: ['Camera make', 'device'],
  0x0110: ['Camera model', 'device'],
  0x0112: ['Orientation', 'capture', first((n) => ENUM.orientation[n])],
  0x0131: ['Software', 'software'],
  0x0132: ['Modified', 'datetime'],
  0x013b: ['Artist', 'identity'],
  0x013c: ['Host computer', 'software'],
  0x4746: ['Rating', 'description', first((n) => `${n} / 5`)],
  0x8298: ['Copyright', 'identity'],
  0x9c9b: ['Title', 'description', ucs2],
  0x9c9c: ['Comment', 'description', ucs2],
  0x9c9d: ['Author', 'identity', ucs2],
  0x9c9e: ['Keywords', 'description', ucs2],
  0x9c9f: ['Subject', 'description', ucs2],
  0x829a: ['Exposure time', 'capture', first((n) => (n >= 1 ? `${round(n)} s` : `1/${Math.round(1 / n)} s`))],
  0x829d: ['Aperture', 'capture', first((n) => `f/${round(n)}`)],
  0x8822: ['Exposure program', 'capture', first((n) => ENUM.program[n])],
  0x8827: ['ISO', 'capture', first(String)],
  0x9003: ['Taken', 'datetime'],
  0x9004: ['Digitised', 'datetime'],
  0x9010: ['Time zone (modified)', 'datetime'],
  0x9011: ['Time zone (taken)', 'datetime'],
  0x9012: ['Time zone (digitised)', 'datetime'],
  0x9204: ['Exposure compensation', 'capture', first((n) => `${round(n)} EV`)],
  0x9207: ['Metering mode', 'capture', first((n) => ENUM.metering[n])],
  0x9209: ['Flash', 'capture', first((n) => (n & 1 ? 'Fired' : 'Did not fire'))],
  0x920a: ['Focal length', 'capture', first((n) => `${round(n)} mm`)],
  0x9286: ['User comment', 'description'],
  0xa402: ['Exposure mode', 'capture', first((n) => ENUM.exposureMode[n])],
  0xa403: ['White balance', 'capture', first((n) => ENUM.whiteBalance[n])],
  0xa404: ['Digital zoom', 'capture', first((n) => (n ? `${round(n, 2)}×` : ''))],
  0xa405: ['Focal length (35 mm)', 'capture', first((n) => `${n} mm`)],
  0xa406: ['Scene type', 'capture', first((n) => ENUM.scene[n])],
  0xa420: ['Image unique ID', 'tracking'],
  0xa430: ['Camera owner', 'identity'],
  0xa431: ['Body serial number', 'device'],
  0xa432: ['Lens specification', 'device', (v) => (Array.isArray(v) && v.length === 4 ? `${round(v[0])}–${round(v[1])} mm f/${round(v[2])}–${round(v[3])}` : '')],
  0xa433: ['Lens make', 'device'],
  0xa434: ['Lens model', 'device'],
  0xa435: ['Lens serial number', 'device'],
};
// Pointers and pure structure; not worth reporting individually.
const STRUCTURAL = new Set([0x8769, 0x8825, 0xa005, 0x0201, 0x0202, 0x927c, 0x02bc, 0x83bb, 0x8773, 0x0100, 0x0101, 0x0102, 0x0103, 0x0106, 0x0111, 0x0115, 0x0116, 0x0117, 0x011c]);

function makerVendor(note, make) {
  const head = latin1.decode(note.subarray(0, 12));
  for (const [re, name] of [[/^Apple iOS/, 'Apple'], [/^Nikon/, 'Nikon'], [/^OLYMP|^OM SYSTEM/, 'Olympus'], [/^FUJIFILM/, 'Fujifilm'], [/^Panasonic/, 'Panasonic'], [/^SONY/, 'Sony'], [/^LEICA/, 'Leica'], [/^SAMSUNG/i, 'Samsung'], [/^Ricoh|^PENTAX|^AOC/, 'Pentax / Ricoh'], [/^HUAWEI/, 'Huawei'], [/^GOOGLE/, 'Google']]) {
    if (re.test(head)) return name;
  }
  return make || 'manufacturer';
}

function parseExif(tiff, r, src = 'EXIF') {
  const t = tiffReader(tiff);
  if (!t) return;
  let other = 0;
  let make = '';

  const report = (tags) => {
    for (const [tag, v] of tags) {
      if (v == null) continue;
      const def = EXIF_TAGS[tag];
      if (def) {
        const [name, cat, f] = def;
        const out = tag === 0x9286 ? userComment(v, t.le) : f ? f(v) : text(v);
        if (tag === 0x010f) make = clean(out);
        r.field(cat, name, out, src);
      } else if (!STRUCTURAL.has(tag)) other++;
    }
  };

  const ifd0 = t.ifd(t.first);
  report(ifd0.tags);
  const exif = t.ifd(ifd0.tags.get(0x8769)?.[0]);
  report(exif.tags);

  const note = exif.tags.get(0x927c);
  if (note instanceof Uint8Array && note.length) {
    const vendor = makerVendor(note, make);
    r.field('device', 'Maker notes', `${fmtBytes(note.length)} of proprietary ${vendor} data${vendor === 'Apple' ? ' (can include Live Photo and burst identifiers)' : ' (often includes serial numbers and internal settings)'}`, src);
  }

  // XMP / IPTC / ICC can also sit inside TIFF-style EXIF (PNG eXIf, WebP EXIF).
  const xmp = ifd0.tags.get(0x02bc);
  if (xmp instanceof Uint8Array) parseXmp(utf8.decode(xmp), r, `${src} XMP`);
  const iptc = ifd0.tags.get(0x83bb);
  if (iptc instanceof Uint8Array) parseIim(iptc, r);
  const icc = ifd0.tags.get(0x8773);
  if (icc instanceof Uint8Array) parseIcc(icc, r);

  parseGps(t.ifd(ifd0.tags.get(0x8825)?.[0]).tags, r, src);

  // IFD1: the embedded thumbnail. It is made at capture time, so it can show the frame before cropping or edits.
  if (ifd0.next) {
    const ifd1 = t.ifd(ifd0.next).tags;
    const off = ifd1.get(0x0201)?.[0];
    const len = ifd1.get(0x0202)?.[0];
    if (off && len && off + len <= tiff.length) {
      const thumb = tiff.slice(off, off + len);
      r.field('hidden', 'Embedded thumbnail', `${fmtBytes(len)} JPEG preview, made before any cropping or edits`, src);
      if (thumb[0] === 0xff && thumb[1] === 0xd8) r.thumbnails.push(thumb);
    }
  }
  if (other) r.field('other', 'Other EXIF tags', `${other} technical tag${other === 1 ? '' : 's'} (resolution, colour space, exposure details…)`, src);
}

function parseGps(g, r, src) {
  if (!g.size) return;
  const ref = (tag) => text(g.get(tag)).trim().charAt(0).toUpperCase();
  const dms = (v) => (Array.isArray(v) && v.length >= 3 ? v[0] + v[1] / 60 + v[2] / 3600 : null);
  const lat = dms(g.get(2));
  const lon = dms(g.get(4));
  if (lat != null && lon != null && (lat || lon)) {
    const la = lat * (ref(1) === 'S' ? -1 : 1);
    const lo = lon * (ref(3) === 'W' ? -1 : 1);
    if (Number.isFinite(la) && Number.isFinite(lo)) {
      r.field('location', 'GPS coordinates', `${la.toFixed(6)}, ${lo.toFixed(6)}`, src);
      r.gps ??= { lat: la, lon: lo };
    }
  } else if (!r.gps) {
    r.field('location', 'GPS data', 'Present (no usable coordinates)', src);
  }
  const alt = g.get(6)?.[0];
  if (Number.isFinite(alt)) {
    const below = g.get(5)?.[0] === 1;
    r.field('location', 'Altitude', `${round(alt)} m ${below ? 'below' : 'above'} sea level`, src);
    if (r.gps && r.gps.alt == null) r.gps.alt = below ? -alt : alt;
  }
  const dir = g.get(17)?.[0];
  if (Number.isFinite(dir)) r.field('location', 'Camera heading', `${Math.round(dir)}° (${ref(16) === 'M' ? 'magnetic' : 'true'} north)`, src);
  const speed = g.get(13)?.[0];
  if (Number.isFinite(speed)) r.field('location', 'Speed', `${round(speed)} ${{ K: 'km/h', M: 'mph', N: 'knots' }[ref(12)] || 'km/h'}`, src);
  const err = g.get(31)?.[0];
  if (Number.isFinite(err)) r.field('location', 'Position accuracy', `±${round(err)} m`, src);
  const time = g.get(7);
  const date = text(g.get(29));
  if (Array.isArray(time) && time.length === 3) {
    const hms = time.map((n) => String(Math.floor(n)).padStart(2, '0')).join(':');
    r.field('location', 'GPS timestamp', `${date ? `${date} ` : ''}${hms} UTC`, src);
  }
  const method = g.get(27);
  if (method) r.field('location', 'Positioning method', userComment(method, true), src);
}

// --- XMP --------------------------------------------------------------------
const XMP_TAGS = {
  'tiff:Make': ['Camera make', 'device'], 'tiff:Model': ['Camera model', 'device'],
  'aux:SerialNumber': ['Body serial number', 'device'], 'exifEX:BodySerialNumber': ['Body serial number', 'device'],
  'aux:Lens': ['Lens', 'device'], 'exifEX:LensModel': ['Lens model', 'device'], 'exifEX:LensMake': ['Lens make', 'device'],
  'aux:LensSerialNumber': ['Lens serial number', 'device'], 'exifEX:LensSerialNumber': ['Lens serial number', 'device'],
  'aux:OwnerName': ['Camera owner', 'identity'], 'exifEX:CameraOwnerName': ['Camera owner', 'identity'],
  'xmp:CreatorTool': ['Creator tool', 'software'], 'tiff:Software': ['Software', 'software'], 'photoshop:History': ['Photoshop history', 'software'],
  'xmp:CreateDate': ['Created', 'datetime'], 'xmp:ModifyDate': ['Modified', 'datetime'], 'xmp:MetadataDate': ['Metadata modified', 'datetime'],
  'photoshop:DateCreated': ['Date created', 'datetime'], 'exif:DateTimeOriginal': ['Taken', 'datetime'], 'exif:DateTimeDigitized': ['Digitised', 'datetime'],
  'dc:creator': ['Creator', 'identity'], 'dc:rights': ['Rights', 'identity'], 'dc:publisher': ['Publisher', 'identity'], 'dc:contributor': ['Contributor', 'identity'],
  'xmpRights:Owner': ['Rights owner', 'identity'], 'xmpRights:WebStatement': ['Rights URL', 'identity'], 'xmpRights:UsageTerms': ['Usage terms', 'identity'],
  'photoshop:AuthorsPosition': ['Author title', 'identity'], 'photoshop:Credit': ['Credit', 'identity'], 'photoshop:Source': ['Source', 'identity'], 'photoshop:CaptionWriter': ['Caption writer', 'identity'],
  'Iptc4xmpCore:CiEmailWork': ['Email', 'identity'], 'Iptc4xmpCore:CiTelWork': ['Phone', 'identity'], 'Iptc4xmpCore:CiUrlWork': ['Website', 'identity'],
  'Iptc4xmpCore:CiAdrExtadr': ['Street address', 'identity'], 'Iptc4xmpCore:CiAdrCity': ['Contact city', 'identity'], 'Iptc4xmpCore:CiAdrRegion': ['Contact region', 'identity'],
  'Iptc4xmpCore:CiAdrPcode': ['Postcode', 'identity'], 'Iptc4xmpCore:CiAdrCtry': ['Contact country', 'identity'],
  'dc:title': ['Title', 'description'], 'dc:description': ['Description', 'description'], 'dc:subject': ['Keywords', 'description'],
  'photoshop:Headline': ['Headline', 'description'], 'photoshop:Instructions': ['Instructions', 'description'], 'photoshop:Category': ['Category', 'description'],
  'xmp:Rating': ['Rating', 'description'], 'xmp:Label': ['Label', 'description'], 'lr:hierarchicalSubject': ['Keyword hierarchy', 'description'], 'xmp:Nickname': ['Nickname', 'description'],
  'photoshop:City': ['City', 'location'], 'photoshop:State': ['State / province', 'location'], 'photoshop:Country': ['Country', 'location'],
  'Iptc4xmpCore:Location': ['Sublocation', 'location'], 'Iptc4xmpCore:CountryCode': ['Country code', 'location'],
  'Iptc4xmpExt:City': ['City', 'location'], 'Iptc4xmpExt:Sublocation': ['Sublocation', 'location'], 'Iptc4xmpExt:ProvinceState': ['State / province', 'location'],
  'Iptc4xmpExt:CountryName': ['Country', 'location'], 'Iptc4xmpExt:CountryCode': ['Country code', 'location'],
  'exif:GPSLatitude': ['GPS latitude', 'location'], 'exif:GPSLongitude': ['GPS longitude', 'location'], 'exif:GPSAltitude': ['GPS altitude', 'location'],
  'exif:GPSImgDirection': ['Camera heading', 'location'], 'exif:GPSTimeStamp': ['GPS timestamp', 'location'],
  'xmpMM:DocumentID': ['Document ID', 'tracking'], 'xmpMM:InstanceID': ['Instance ID', 'tracking'], 'xmpMM:OriginalDocumentID': ['Original document ID', 'tracking'],
  'stRef:documentID': ['Derived from document', 'tracking'], 'stRef:originalDocumentID': ['Derived from original', 'tracking'],
  'photoshop:DocumentAncestors': ['Ancestor documents', 'tracking'], 'exif:ImageUniqueID': ['Image unique ID', 'tracking'], 'xmpMM:PreservedFileName': ['Original file name', 'tracking'],
  'Iptc4xmpExt:DigitalSourceType': ['Digital source type', 'ai'], 'Iptc4xmpExt:AISystemUsed': ['AI system', 'ai'], 'Iptc4xmpExt:AISystemVersionUsed': ['AI system version', 'ai'],
  'Iptc4xmpExt:AIPromptInformation': ['Prompt', 'ai'], 'Iptc4xmpExt:AIPromptWriterName': ['Prompt writer', 'ai'],
  'Iptc4xmpExt:PersonInImage': ['Person in image', 'people'], 'MPReg:PersonDisplayName': ['Tagged person', 'people'], 'MP:PersonDisplayName': ['Tagged person', 'people'],
  'GCamera:MotionPhoto': ['Motion photo', 'hidden'], 'GCamera:MicroVideo': ['Motion photo (micro video)', 'hidden'], 'GCamera:MicroVideoOffset': ['Motion photo video offset', 'hidden'],
  'GDepth:Format': ['Depth map', 'hidden'], 'GImage:Mime': ['Hidden secondary image', 'hidden'], 'hdrgm:Version': ['HDR gain map', 'hidden'],
  'GCamera:SpecialTypeID': ['Special capture type', 'capture'], 'GPano:ProjectionType': ['Panorama projection', 'capture'],
  'exif:ExposureTime': ['Exposure time', 'capture'], 'exif:FNumber': ['Aperture', 'capture'], 'exif:ISOSpeedRatings': ['ISO', 'capture'], 'exif:FocalLength': ['Focal length', 'capture'],
  'photoshop:ICCProfile': ['ICC profile', 'color'],
};
const XMP_TECH = /^(exif|exifEX|tiff|aux|GPano|GCamera|Camera|drone-dji|apple-fi):/;
const XMP_SKIP = /^(rdf|x|xml|xmlns|stEvt|stRef|stDim|stFnt|stMfs|xmpG|xmpTPg|crs|mwg-rs|mwg-kw|MPRI|MPReg|stArea|Item|Container|xmpNote):|^(dc:format|photoshop:ColorMode|tiff:(XResolution|YResolution|ResolutionUnit|ImageWidth|ImageLength|Orientation|BitsPerSample|PhotometricInterpretation|SamplesPerPixel)|exif:(PixelXDimension|PixelYDimension|ColorSpace|ExifVersion|FlashpixVersion|NativeDigest)|tiff:NativeDigest|xmpMM:History|xmpMM:DerivedFrom|xmpMM:Ingredients|xmpMM:Pantry|xmpMM:Manifest)$/;
const SOURCE_TYPES = {
  trainedAlgorithmicMedia: 'AI-generated (trained algorithmic media)',
  compositeWithTrainedAlgorithmicMedia: 'Composite including AI-generated elements',
  algorithmicMedia: 'Algorithmically generated',
  compositeSynthetic: 'Composite with synthetic elements',
  digitalCapture: 'Original camera capture',
  computationalCapture: 'Computational camera capture',
  minorHumanEdits: 'Captured, minor edits',
  digitalArt: 'Digital art',
  virtualRecording: 'Virtual recording',
  screenCapture: 'Screenshot',
};

function parseXmp(xml, r, src = 'XMP') {
  const start = [xml.indexOf('<x:xmpmeta'), xml.indexOf('<rdf:RDF')].filter((i) => i >= 0).sort((a, b) => a - b)[0];
  if (start == null) return;
  const closeTag = xml.startsWith('<x:xmpmeta', start) ? '</x:xmpmeta>' : '</rdf:RDF>';
  const end = xml.indexOf(closeTag, start);
  const body = xml.slice(start, end < 0 ? undefined : end + closeTag.length);

  let crs = 0;
  const unknown = [];
  const prop = (name, value) => {
    value = clean(value);
    if (!value) return;
    if (name.startsWith('crs:')) { crs++; return; }
    const def = XMP_TAGS[name];
    if (def) {
      const [label, cat] = def;
      if (name === 'Iptc4xmpExt:DigitalSourceType') value = SOURCE_TYPES[value.split('/').pop()] || value;
      if (name === 'GCamera:MotionPhoto' || name === 'GCamera:MicroVideo') value = value === '1' ? 'Yes: a short video clip is appended to this photo' : value;
      if (name === 'hdrgm:Version') value = `Version ${value}: a second hidden image used for HDR display`;
      if (name === 'GDepth:Format') value = `${value}: a hidden depth image of the scene`;
      r.field(cat, label, value, src);
    } else if (!XMP_SKIP.test(name)) {
      unknown.push([name, value]);
    }
  };

  if (typeof DOMParser !== 'undefined') {
    const doc = new DOMParser().parseFromString(body, 'application/xml');
    if (!doc.getElementsByTagName('parsererror').length) {
      walkXmp(doc.documentElement, prop, r, src);
      flushXmp(unknown, crs, r, src);
      return;
    }
  }
  // Malformed XML: fall back to pattern matching.
  for (const [, name, value] of body.matchAll(/\s([\w-]+:[\w-]+)="([^"]*)"/g)) prop(name, value);
  for (const [, name, value] of body.matchAll(/<([\w-]+:[\w-]+)>([^<]+)<\/\1>/g)) prop(name, value);
  flushXmp(unknown, crs, r, src);
}

function flushXmp(unknown, crs, r, src) {
  if (crs) r.field('software', 'Lightroom / Camera Raw settings', `${crs} develop settings (exposure, crop, colour grading…)`, src);
  for (const [name, value] of unknown.slice(0, 40)) r.field(XMP_TECH.test(name) ? 'capture' : 'other', name, value, src);
  if (unknown.length > 40) r.field('other', 'More XMP properties', `${unknown.length - 40} more`, src);
}

function attrsOf(el, prop) {
  for (const a of el.attributes) if (!/^(xmlns|rdf:|xml:)/.test(a.name)) prop(a.name, a.value);
}

function walkXmp(el, prop, r, src) {
  attrsOf(el, prop);
  for (const c of el.children) {
    const name = c.tagName;
    if (/^(rdf|x):/.test(name)) { walkXmp(c, prop, r, src); continue; }
    if (name === 'xmpMM:History') { xmpHistory(c, r, src); continue; }
    if (name === 'mwg-rs:Regions' || name === 'MP:RegionInfo') { xmpRegions(c, r, src); continue; }
    if (name === 'GContainer:Directory' || name === 'Container:Directory') { xmpContainer(c, r, src); continue; }
    attrsOf(c, prop);
    if (!c.children.length) { prop(name, c.textContent); continue; }
    const lis = [...c.getElementsByTagName('rdf:li')];
    if (lis.length && lis.every((li) => !li.children.length && [...li.attributes].every((a) => /^(xml|rdf):/.test(a.name)))) {
      prop(name, lis.map((li) => li.textContent.trim()).filter(Boolean).join(', '));
    } else {
      walkXmp(c, prop, r, src);
    }
  }
}

// Values of a property anywhere under el, as attribute or element.
function collect(el, qname) {
  const out = [...el.getElementsByTagName(qname)].map((e) => e.textContent.trim());
  for (const e of el.getElementsByTagName('*')) if (e.hasAttribute(qname)) out.push(e.getAttribute(qname));
  if (el.hasAttribute?.(qname)) out.push(el.getAttribute(qname));
  return out.filter(Boolean);
}

function xmpHistory(el, r, src) {
  const steps = [...el.getElementsByTagName('rdf:li')];
  if (!steps.length) return;
  const actions = collect(el, 'stEvt:action');
  const agents = [...new Set(collect(el, 'stEvt:softwareAgent'))];
  const when = collect(el, 'stEvt:when').sort();
  r.field('software', 'Edit history', `${steps.length} step${steps.length === 1 ? '' : 's'}: ${[...new Set(actions)].join(', ') || 'unknown actions'}`, src);
  if (agents.length) r.field('software', 'Edited with', agents.join(', '), src);
  if (when.length) r.field('datetime', 'Edit history span', when.length > 1 ? `${when[0]} → ${when.at(-1)}` : when[0], src);
}

function xmpRegions(el, r, src) {
  const names = [...new Set([...collect(el, 'mwg-rs:Name'), ...collect(el, 'MPReg:PersonDisplayName')])];
  const types = collect(el, 'mwg-rs:Type');
  const faces = types.filter((t) => t === 'Face').length || el.getElementsByTagName('rdf:li').length;
  if (faces) r.field('people', 'Face regions', `${faces} region${faces === 1 ? '' : 's'} marked in the image`, src);
  for (const n of names) r.field('people', 'Tagged person', n, src);
}

function xmpContainer(el, r, src) {
  const items = collect(el, 'Item:Semantic').filter((s) => s !== 'Primary');
  const mimes = collect(el, 'Item:Mime');
  if (items.length) r.field('hidden', 'Embedded items', `${items.join(', ')} (${mimes.filter((m) => m !== 'image/jpeg').join(', ') || 'image/jpeg'})`, src);
}

// --- IPTC (IIM) inside Photoshop resource blocks ------------------------------
const IIM = {
  5: ['Title', 'description'], 15: ['Category', 'description'], 20: ['Supplemental category', 'description'], 25: ['Keywords', 'description'],
  40: ['Instructions', 'description'], 55: ['Date created', 'datetime'], 60: ['Time created', 'datetime'], 62: ['Digital creation date', 'datetime'],
  63: ['Digital creation time', 'datetime'], 65: ['Originating program', 'software'], 70: ['Program version', 'software'],
  80: ['By-line (author)', 'identity'], 85: ['Author title', 'identity'], 90: ['City', 'location'], 92: ['Sublocation', 'location'],
  95: ['State / province', 'location'], 100: ['Country code', 'location'], 101: ['Country', 'location'], 103: ['Transmission reference', 'tracking'],
  105: ['Headline', 'description'], 110: ['Credit', 'identity'], 115: ['Source', 'identity'], 116: ['Copyright', 'identity'],
  118: ['Contact', 'identity'], 120: ['Caption', 'description'], 122: ['Caption writer', 'identity'],
};

function parseIim(data, r) {
  const values = new Map();
  let isUtf8 = false;
  let other = 0;
  for (let i = 0; i + 5 <= data.length && data[i] === 0x1c;) {
    const rec = data[i + 1];
    const ds = data[i + 2];
    let len = (data[i + 3] << 8) | data[i + 4];
    let p = i + 5;
    if (len & 0x8000) { // extended length
      const n = len & 0x7fff;
      len = 0;
      for (let k = 0; k < n; k++) len = len * 256 + data[p + k];
      p += n;
    }
    const v = data.subarray(p, p + len);
    if (rec === 1 && ds === 90) isUtf8 = v[0] === 0x1b && v[1] === 0x25 && v[2] === 0x47;
    if (rec === 2 && IIM[ds]) values.set(ds, [...(values.get(ds) || []), v]);
    else if (rec === 2 && ds !== 0) other++;
    i = p + len;
  }
  for (const [ds, list] of values) {
    const [name, cat] = IIM[ds];
    r.field(cat, name, list.map((v) => (isUtf8 ? utf8 : latin1).decode(v)).join(', '), 'IPTC');
  }
  if (other) r.field('other', 'Other IPTC fields', `${other}`, 'IPTC');
}

function parsePhotoshop(seg, r) {
  let i = 0;
  while (i + 12 <= seg.length && startsWith(seg, '8BIM', i)) {
    const id = (seg[i + 4] << 8) | seg[i + 5];
    let p = i + 6;
    const nameLen = seg[p];
    p += 1 + nameLen + ((nameLen + 1) & 1);
    const size = ((seg[p] << 24) | (seg[p + 1] << 16) | (seg[p + 2] << 8) | seg[p + 3]) >>> 0;
    p += 4;
    const data = seg.subarray(p, p + size);
    if (id === 0x0404) parseIim(data, r);
    else if (id === 0x0409 || id === 0x040c) {
      r.field('hidden', 'Photoshop thumbnail', `${fmtBytes(size)} JPEG preview`, 'Photoshop');
      const jpeg = data.subarray(28);
      if (jpeg[0] === 0xff && jpeg[1] === 0xd8) r.thumbnails.push(jpeg.slice());
    } else if (id === 0x0422) parseExif(startsWith(data, 'Exif\0\0') ? data.subarray(6) : data, r, 'Photoshop EXIF');
    else if (id === 0x0424) parseXmp(utf8.decode(data), r, 'Photoshop XMP');
    else if (id === 0x040f) parseIcc(data, r);
    else if (id === 0x0bb7) r.field('software', 'Clipping path', latin1.decode(data.subarray(1, 1 + data[0])) || 'Present', 'Photoshop');
    i = p + size + (size & 1);
  }
}

// --- ICC profile ------------------------------------------------------------
const ICC_VENDORS = { APPL: 'Apple', MSFT: 'Microsoft', GOOG: 'Google', ADBE: 'Adobe', lcms: 'Little CMS', SGI: 'SGI', KODA: 'Kodak', HP: 'HP', EPSO: 'Epson', CANO: 'Canon', NKON: 'Nikon', SONY: 'Sony', SAMS: 'Samsung' };

function parseIcc(data, r) {
  if (data.length < 132) return;
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let desc = '';
  const n = Math.min(v.getUint32(128), 100);
  for (let i = 0; i < n && 132 + i * 12 + 12 <= data.length; i++) {
    const o = 132 + i * 12;
    if (latin1.decode(data.subarray(o, o + 4)) !== 'desc') continue;
    const off = v.getUint32(o + 4);
    if (off + 16 > data.length) break;
    const type = latin1.decode(data.subarray(off, off + 4));
    if (type === 'desc') desc = latin1.decode(data.subarray(off + 12, off + 12 + v.getUint32(off + 8) - 1));
    else if (type === 'mluc' && off + 28 <= data.length) {
      const len = v.getUint32(off + 20);
      const at = off + v.getUint32(off + 24);
      desc = utf16be.decode(data.subarray(at, at + len));
    }
  }
  r.field('color', 'Colour profile', desc || 'Unnamed profile', 'ICC');
  const vendor = (o) => latin1.decode(data.subarray(o, o + 4)).replace(/\0/g, '').trim();
  const maker = ICC_VENDORS[vendor(80)] || ICC_VENDORS[vendor(4)] || ICC_VENDORS[vendor(40)];
  if (maker) r.field('color', 'Profile made by', maker, 'ICC');
}

// --- C2PA (JUMBF / CBOR) ----------------------------------------------------
function cborText(bytes, p) {
  const b = bytes[p];
  if (b >> 5 !== 3) return null;
  let len = b & 31;
  let q = p + 1;
  if (len === 24) len = bytes[q++];
  else if (len === 25) { len = (bytes[q] << 8) | bytes[q + 1]; q += 2; }
  else if (len > 25) return null;
  return utf8.decode(bytes.subarray(q, q + len));
}

// Text values that follow a CBOR text key.
function cborValues(bytes, key) {
  const out = [];
  const head = key.length < 24 ? [0x60 + key.length] : [0x78, key.length];
  for (let i = 0; (i = indexOf(bytes, key, i)) >= 0; i += key.length) {
    if (head.every((b, k) => bytes[i - head.length + k] === b)) {
      const v = cborText(bytes, i + key.length);
      if (v) out.push(v);
    }
  }
  return [...new Set(out)];
}

// X.509 subject/issuer names inside the signature (organisationName 2.5.4.10, commonName 2.5.4.3).
function certNames(bytes, oid) {
  const out = [];
  for (let i = 0; i + 6 < bytes.length; i++) {
    if (bytes[i] === 0x06 && bytes[i + 1] === 0x03 && bytes[i + 2] === 0x55 && bytes[i + 3] === 0x04 && bytes[i + 4] === oid) {
      const tag = bytes[i + 5];
      const len = bytes[i + 6];
      if ([0x0c, 0x13, 0x16, 0x14].includes(tag) && len < 0x80) out.push(utf8.decode(bytes.subarray(i + 7, i + 7 + len)));
    }
  }
  return [...new Set(out)];
}

// No \b anchors: the CBOR length bytes around an action string are often ASCII letters.
const C2PA_ACTIONS = /c2pa\.(color_adjustments|created|opened|edited|placed|cropped|resized|filtered|drawing|converted|published|transcoded|repackaged|removed|redacted|orientation|watermarked(?:\.unbound|\.bound)?|unknown)/g;

function parseC2pa(bytes, r, src = 'C2PA') {
  const raw = latin1.decode(bytes);
  const gens = [...cborValues(bytes, 'claim_generator'), ...cborValues(bytes, 'softwareAgent')];
  const infoAt = indexOf(bytes, 'claim_generator_info');
  if (infoAt >= 0) gens.push(...cborValues(bytes.subarray(infoAt, infoAt + 300), 'name'));
  r.field('provenance', 'Content Credentials manifest', 'Present: a signed record of how this file was made', src);
  if (gens.length) r.field('provenance', 'Made with', [...new Set(gens)].join(', '), src);
  const orgs = certNames(bytes, 0x0a);
  const cns = certNames(bytes, 0x03);
  if (orgs.length) r.field('provenance', 'Signed by', orgs.join(', '), src);
  if (cns.length) r.field('provenance', 'Certificate', cns.join(', '), src);
  const actions = [...new Set([...raw.matchAll(C2PA_ACTIONS)].map((m) => m[1].replace('_', ' ')))];
  if (actions.length) r.field('provenance', 'Recorded actions', actions.join(', '), src);
  const sourceType = /digitalsourcetype\/(\w+)/i.exec(raw)?.[1];
  if (sourceType) r.field(/algorithmic|synthetic/i.test(sourceType) ? 'ai' : 'provenance', 'Digital source type', SOURCE_TYPES[sourceType] || sourceType, src);
  for (const t of cborValues(bytes, 'dc:title')) r.field('description', 'Title', t, src);
  for (const id of cborValues(bytes, 'instanceID').slice(0, 3)) r.field('tracking', 'Credentials instance ID', id, src);
  if (/c2pa\.thumbnail/.test(raw)) r.field('hidden', 'Credentials thumbnail', 'A preview image stored inside the manifest', src);
  const ingredients = (raw.match(/c2pa\.ingredient/g) || []).length;
  if (ingredients) r.field('provenance', 'Ingredients', `${ingredients} source file reference${ingredients === 1 ? '' : 's'}`, src);
  if (/c2pa\.watermarked/.test(raw)) r.field('provenance', 'Invisible watermark', 'Declared by the generator. It lives in the pixels and survives metadata removal.', src);
}

// --- AI generator parameters ------------------------------------------------
const A1111_KEYS = new Set(['Steps', 'Sampler', 'Schedule type', 'CFG scale', 'Seed', 'Size', 'Model hash', 'Model', 'VAE', 'VAE hash', 'Denoising strength', 'Clip skip', 'Hires upscale', 'Hires upscaler', 'Hires steps', 'Lora hashes', 'Version', 'Face restoration', 'Distilled CFG Scale', 'Module 1']);

function parseA1111(text, r, src) {
  const neg = /\n?Negative prompt:\s*/.exec(text);
  const steps = text.search(/\n?Steps: \d/);
  const prompt = text.slice(0, neg ? neg.index : steps >= 0 ? steps : undefined).trim();
  if (prompt) r.field('ai', 'Prompt', prompt, src);
  if (neg) r.field('ai', 'Negative prompt', text.slice(neg.index + neg[0].length, steps > neg.index ? steps : undefined), src);
  if (steps >= 0) {
    for (const [, k, v] of text.slice(steps).matchAll(/([A-Za-z][\w ]{1,30}):\s*("[^"]*"|[^,\n]+)/g)) {
      if (A1111_KEYS.has(k.trim())) r.field('ai', k.trim(), v.replace(/^"|"$/g, ''), src);
    }
  }
}

const AI_KEYS = [
  [/^(prompt|positive_prompt|positivePrompt|caption)$/, 'Prompt'],
  [/^(negative_prompt|negativePrompt|uc|negative)$/, 'Negative prompt'],
  [/^(seed|noise_seed)$/, 'Seed'], [/^steps$/, 'Steps'], [/^(cfg_scale|cfg|scale|guidance_scale)$/, 'CFG scale'],
  [/^(sampler|sampler_name|scheduler)$/, 'Sampler'], [/^(model|model_name|base_model|ckpt_name|unet_name|model_hash)$/, 'Model'],
  [/^lora_name$/, 'LoRA'], [/^(width|height)$/, null],
];

// Generic walk over a generator's JSON (InvokeAI, NovelAI, Fooocus, ComfyUI prompt graphs).
function parseAiJson(json, r, src) {
  let obj;
  try { obj = JSON.parse(json); } catch { return false; }
  if (!obj || typeof obj !== 'object') return false;
  let nodes = 0;
  const visit = (o, depth) => {
    if (!o || typeof o !== 'object' || depth > 6) return;
    if (o.class_type || o.type) nodes++;
    if (typeof o.class_type === 'string' && /CLIPTextEncode/.test(o.class_type) && typeof o.inputs?.text === 'string') r.field('ai', 'Prompt', o.inputs.text, src);
    if (Array.isArray(o.widgets_values) && /CLIPTextEncode/.test(o.type || '') && typeof o.widgets_values[0] === 'string') r.field('ai', 'Prompt', o.widgets_values[0], src);
    if (Array.isArray(o.widgets_values) && /CheckpointLoader|UNETLoader|LoraLoader/.test(o.type || '') && typeof o.widgets_values[0] === 'string') r.field('ai', /Lora/.test(o.type) ? 'LoRA' : 'Model', o.widgets_values[0], src);
    for (const [k, v] of Object.entries(o)) {
      if (v == null) continue;
      if (typeof v === 'object') { visit(v, depth + 1); continue; }
      const hit = AI_KEYS.find(([re]) => re.test(k));
      if (hit?.[1] && (typeof v === 'string' || typeof v === 'number')) r.field('ai', hit[1], String(v), src);
    }
  };
  visit(obj, 0);
  if (nodes > 2) r.field('ai', 'Workflow', `${nodes} node graph`, src);
  return true;
}

// --- PNG text chunks --------------------------------------------------------
const PNG_TEXT = {
  Software: ['Software', 'software'], Author: ['Author', 'identity'], Copyright: ['Copyright', 'identity'],
  'Creation Time': ['Created', 'datetime'], 'date:create': ['Created', 'datetime'], 'date:modify': ['Modified', 'datetime'], 'date:timestamp': ['Timestamp', 'datetime'],
  Title: ['Title', 'description'], Description: ['Description', 'description'], Comment: ['Comment', 'description'],
  Disclaimer: ['Disclaimer', 'description'], Warning: ['Warning', 'description'], Source: ['Source', 'software'], URL: ['URL', 'identity'],
};

function hexProfile(text) {
  const hex = text.trim().split('\n').slice(2).join('').replace(/\s+/g, '');
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function pngText(keyword, text, r) {
  const src = `PNG “${keyword}”`;
  if (keyword === 'XML:com.adobe.xmp') return parseXmp(text, r);
  if (keyword === 'parameters') return text.trimStart().startsWith('{') ? parseAiJson(text, r, src) : parseA1111(text, r, src);
  if (['prompt', 'workflow', 'sd-metadata', 'invokeai_metadata', 'invokeai_graph', 'generation_data'].includes(keyword)) {
    if (!parseAiJson(text, r, src)) r.field('ai', keyword, text, src);
    return;
  }
  if (keyword === 'Dream') return r.field('ai', 'Prompt', text, src);
  if (/^Raw profile type (exif|APP1)$/i.test(keyword)) {
    const b = hexProfile(text);
    return parseExif(startsWith(b, 'Exif\0\0') ? b.subarray(6) : b, r, src);
  }
  if (/^Raw profile type iptc$/i.test(keyword)) { const b = hexProfile(text); return startsWith(b, 'Photoshop 3.0') ? parsePhotoshop(b.subarray(14), r) : parseIim(b, r); }
  if (/^Raw profile type xmp$/i.test(keyword)) return parseXmp(utf8.decode(hexProfile(text)), r);
  if (keyword === 'Comment' && text.trimStart().startsWith('{') && parseAiJson(text, r, src)) return;
  const def = PNG_TEXT[keyword];
  if (def) r.field(def[1], def[0], text, src);
  else r.field('description', `Text “${keyword}”`, text, src);
}

// --- container walkers ------------------------------------------------------
// Skip entropy-coded scan data to the next real marker (0xFF00 is stuffing, RSTn are in-scan).
function skipScan(bytes, p) {
  while ((p = bytes.indexOf(0xff, p)) >= 0 && p + 1 < bytes.length) {
    const b = bytes[p + 1];
    if (b === 0x00 || (b >= 0xd0 && b <= 0xd7)) p += 2;
    else if (b === 0xff) p += 1;
    else return p;
  }
  return bytes.length;
}

function walkJpeg(bytes, r) {
  let i = 2;
  const icc = [];
  let end = bytes.length;
  while (i + 4 <= bytes.length) {
    if (bytes[i] !== 0xff) break;
    const marker = bytes[i + 1];
    if (marker === 0xff) { i++; continue; }
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { i += 2; continue; }
    if (marker === 0xd9) { end = i + 2; break; }
    const len = (bytes[i + 2] << 8) | bytes[i + 3];
    const seg = bytes.subarray(i + 4, i + 2 + len);
    if (marker === 0xda) { i = skipScan(bytes, i + 2 + len); continue; }

    if (marker === 0xe0 && startsWith(seg, 'JFXX')) { r.block('hidden', 'JFIF thumbnail', len); r.field('hidden', 'JFIF thumbnail', `${fmtBytes(len)} preview image`, 'JFIF'); }
    else if (marker === 0xe1 && startsWith(seg, 'Exif\0\0')) { r.block('exif', 'EXIF block', len); parseExif(seg.subarray(6), r); }
    else if (marker === 0xe1 && startsWith(seg, 'http://ns.adobe.com/xap/1.0/')) { const x = utf8.decode(seg); r.block('xmp', 'XMP packet', len, x); parseXmp(x, r); }
    else if (marker === 0xe1 && startsWith(seg, 'http://ns.adobe.com/xmp/extension/')) { r.block('xmp', 'Extended XMP', len, utf8.decode(seg.subarray(0, 4096))); r.field('hidden', 'Extended XMP', `${fmtBytes(len)} extra XMP (usually a depth map or hidden image)`, 'XMP'); }
    else if (marker === 0xe2 && startsWith(seg, 'ICC_PROFILE')) { r.block('icc', 'ICC colour profile', len); icc.push(seg.subarray(14)); }
    else if (marker === 0xe2 && startsWith(seg, 'MPF')) { r.block('hidden', 'Multi-picture index (MPF)', len); parseMpf(seg.subarray(4), r); }
    else if (marker === 0xe2 && startsWith(seg, 'FPXR')) r.block('other', 'FlashPix data', len);
    else if (marker === 0xeb && (indexOf(seg, 'jumb') >= 0 || indexOf(seg, 'c2pa') >= 0)) { r.block('c2pa', 'C2PA / JUMBF manifest', len, latin1.decode(seg)); parseC2pa(seg, r); }
    else if (marker === 0xed && startsWith(seg, 'Photoshop 3.0')) { r.block('iptc', 'IPTC / Photoshop block', len, latin1.decode(seg)); parsePhotoshop(seg.subarray(14), r); }
    else if (marker === 0xec && startsWith(seg, 'Ducky')) { r.block('other', 'Photoshop “Save for Web” block', len); r.field('software', 'Saved with', 'Photoshop Save for Web', 'APP12'); }
    else if (marker === 0xee && startsWith(seg, 'Adobe')) r.block('color', 'Adobe colour transform', len);
    else if (marker === 0xfe) {
      const c = utf8.decode(seg);
      r.block('comment', 'JPEG comment', len, c);
      r.field(/CREATOR:|quality ?=|Lavc|LEAD Tech|Optimi[sz]ed|Intel\(R\) JPEG|Created with/i.test(c) ? 'software' : 'description', 'Comment', c, 'JPEG');
    } else if (marker >= 0xe1 && marker <= 0xef) {
      const name = latin1.decode(seg.subarray(0, 16)).replace(/[^\x20-\x7e].*$/s, '');
      r.block('other', `APP${marker - 0xe0} segment${name ? ` “${name}”` : ''}`, len, latin1.decode(seg));
      r.field('other', `APP${marker - 0xe0} segment`, `${name || 'Unknown'} · ${fmtBytes(len)}`, 'JPEG');
    }
    i += 2 + len;
  }
  if (icc.length) {
    const total = icc.reduce((n, c) => n + c.length, 0);
    const all = new Uint8Array(total);
    icc.reduce((o, c) => (all.set(c, o), o + c.length), 0);
    parseIcc(all, r);
  }
  trailing(bytes, end, r);
}

function parseMpf(tiff, r) {
  const t = tiffReader(tiff);
  if (!t) return;
  const n = t.ifd(t.first).tags.get(0xb001)?.[0];
  if (n > 1) r.field('hidden', 'Extra images in file', `${n - 1} additional image${n > 2 ? 's' : ''} (gain map, depth map or preview)`, 'MPF');
}

// Data glued on after the end-of-image marker: motion-photo videos, gain maps, depth maps.
function trailing(bytes, end, r) {
  const rest = bytes.length - end;
  if (rest < 16) return;
  const tail = bytes.subarray(end);
  const scan = tail.subarray(0, Math.min(tail.length, 1 << 20));
  r.block('hidden', 'Data after end of image', rest);
  if (indexOf(scan, 'ftyp') >= 0 || indexOf(scan, 'MotionPhoto_Data') >= 0) r.field('hidden', 'Embedded video', `${fmtBytes(rest)}: a Live/Motion Photo clip recorded around the shot`, 'Trailer');
  else if (tail[0] === 0xff && tail[1] === 0xd8) r.field('hidden', 'Appended images', `${fmtBytes(rest)} of extra JPEG data (gain map, depth map or preview)`, 'Trailer');
  else r.field('hidden', 'Trailing data', `${fmtBytes(rest)} of unidentified data after the image`, 'Trailer');
}

const PNG_STANDARD = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'sBIT', 'sRGB', 'bKGD', 'hIST', 'pHYs', 'sPLT', 'cICP', 'mDCv', 'cLLi']);

async function walkPng(bytes, r) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let i = 8;
  let end = bytes.length;
  while (i + 12 <= bytes.length) {
    const len = view.getUint32(i);
    const type = latin1.decode(bytes.subarray(i + 4, i + 8));
    const data = bytes.subarray(i + 8, i + 8 + len);
    const size = len + 12;
    if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') {
      const nul = data.indexOf(0);
      const keyword = latin1.decode(data.subarray(0, nul));
      let text = '';
      if (type === 'tEXt') text = latin1.decode(data.subarray(nul + 1));
      else if (type === 'zTXt') text = utf8.decode(await inflate(data.subarray(nul + 2)));
      else {
        const compressed = data[nul + 1] === 1;
        let p = nul + 3;
        p = data.indexOf(0, p) + 1; // language tag
        p = data.indexOf(0, p) + 1; // translated keyword
        const body = data.subarray(p);
        text = utf8.decode(compressed ? await inflate(body) : body);
      }
      const isXmp = keyword === 'XML:com.adobe.xmp';
      const isAi = ['parameters', 'prompt', 'workflow', 'Dream', 'sd-metadata', 'invokeai_metadata', 'invokeai_graph', 'generation_data'].includes(keyword);
      r.block(isXmp ? 'xmp' : isAi ? 'ai' : 'text', isXmp ? 'XMP packet' : `Text chunk “${keyword}”`, size, `${keyword}\n${text}`);
      pngText(keyword, text, r);
    } else if (type === 'eXIf') { r.block('exif', 'EXIF block', size); parseExif(startsWith(data, 'Exif\0\0') ? data.subarray(6) : data, r); }
    else if (type === 'caBX') { r.block('c2pa', 'C2PA manifest (caBX)', size, latin1.decode(data)); parseC2pa(data, r); }
    else if (type === 'iCCP') {
      const nul = data.indexOf(0);
      r.block('icc', 'ICC colour profile', size);
      const profile = await inflate(data.subarray(nul + 2));
      if (profile.length) parseIcc(profile, r);
      else r.field('color', 'Colour profile', latin1.decode(data.subarray(0, nul)), 'ICC');
    } else if (type === 'tIME' && len === 7) {
      r.block('other', 'Modification time', size);
      const p = (n) => String(n).padStart(2, '0');
      r.field('datetime', 'Modified', `${view.getUint16(i + 8)}-${p(data[2])}-${p(data[3])} ${p(data[4])}:${p(data[5])}:${p(data[6])} UTC`, 'PNG');
    } else if (type === 'acTL') {
      r.block('other', 'Animation control', size);
      r.field('other', 'Animated PNG', `${view.getUint32(i + 8)} frames (only the first frame is kept)`, 'PNG');
    } else if (!PNG_STANDARD.has(type) && type !== 'fcTL' && type !== 'fdAT') {
      r.block('other', `Chunk “${type}”`, size, latin1.decode(data.subarray(0, 4096)));
      r.field('other', `Private chunk “${type}”`, fmtBytes(size), 'PNG');
    }
    i += size;
    if (type === 'IEND') { end = i; break; }
  }
  trailing(bytes, end, r);
}

function walkWebp(bytes, r) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let i = 12;
  while (i + 8 <= bytes.length) {
    const type = latin1.decode(bytes.subarray(i, i + 4));
    const len = view.getUint32(i + 4, true);
    const data = bytes.subarray(i + 8, i + 8 + len);
    if (type === 'EXIF') { r.block('exif', 'EXIF block', len + 8); parseExif(startsWith(data, 'Exif\0\0') ? data.subarray(6) : data, r); }
    else if (type === 'XMP ') { const x = utf8.decode(data); r.block('xmp', 'XMP packet', len + 8, x); parseXmp(x, r); }
    else if (type === 'ICCP') { r.block('icc', 'ICC colour profile', len + 8); parseIcc(data, r); }
    else if (type === 'C2PA') { r.block('c2pa', 'C2PA manifest', len + 8, latin1.decode(data)); parseC2pa(data, r); }
    else if (type === 'ANIM') { r.block('other', 'Animation', len + 8); r.field('other', 'Animated WebP', 'Only the first frame is kept', 'WebP'); }
    else if (!['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANMF'].includes(type)) {
      r.block('other', `Chunk “${type.trim()}”`, len + 8);
      r.field('other', `Private chunk “${type.trim()}”`, fmtBytes(len + 8), 'WebP');
    }
    i += 8 + len + (len & 1);
  }
}

// --- MP4 / MOV (ISO BMFF, QuickTime) -----------------------------------------
// Metadata lives in udta / meta / uuid boxes and in the movie and track headers' timestamps.
// Cleaning rewrites those boxes as zero-filled 'free' boxes of the same size, so every sample
// offset in stco/co64 stays valid and the video and audio streams are untouched byte for byte.
const BMFF_CONTAINERS = new Set(['moov', 'trak', 'mdia', 'minf', 'edts', 'dinf']);
const BMFF_META = new Set(['udta', 'meta', 'uuid', 'XMP_']);
const UUID_XMP = 'be7acfcb97a942e89c71999491e3afac';
const UUID_C2PA = 'd8fec3d61b0e483c92975828877ec481';
const QT_EPOCH = Date.UTC(1904, 0, 1);

// QuickTime ©-atoms and Apple / Android mdta keys → category and label.
const QT_ATOMS = {
  '©xyz': ['location', 'GPS location'], loci: ['location', 'Location'], '©mak': ['device', 'Make'], '©mod': ['device', 'Model'],
  '©swr': ['software', 'Software'], '©too': ['software', 'Encoder'], '©enc': ['software', 'Encoded by'], '©fmt': ['software', 'Format'],
  '©day': ['datetime', 'Date'], '©nam': ['description', 'Title'], '©des': ['description', 'Description'], '©cmt': ['description', 'Comment'],
  '©inf': ['description', 'Information'], '©key': ['description', 'Keywords'], desc: ['description', 'Description'], ldes: ['description', 'Long description'],
  '©ART': ['identity', 'Artist'], '©aut': ['identity', 'Author'], '©wrt': ['identity', 'Writer'], '©cpy': ['identity', 'Copyright'], cprt: ['identity', 'Copyright'],
  '©prd': ['identity', 'Producer'], '©dir': ['identity', 'Director'], '©src': ['tracking', 'Source'], '©req': ['software', 'Requirements'],
  auth: ['identity', 'Author'], titl: ['description', 'Title'], dscp: ['description', 'Description'], albm: ['description', 'Album'], yrrc: ['datetime', 'Year'],
  manu: ['device', 'Manufacturer'], modl: ['device', 'Model'], FIRM: ['device', 'Firmware'], LENS: ['device', 'Lens'], CAME: ['device', 'Camera serial'],
  MUID: ['tracking', 'Media unique ID'], GUMI: ['tracking', 'GoPro media ID'], SDLN: ['device', 'Sensor'], aigc: ['ai', 'AIGC label'], AIGC: ['ai', 'AIGC label'],
};
const MDTA_KEYS = [
  [/location\.ISO6709$/, 'location', 'GPS location'], [/location\.(accuracy|body|name|note|role|date)/, 'location', 'Location detail'],
  [/\.make$/, 'device', 'Make'], [/\.model$/, 'device', 'Model'], [/\.software$/, 'software', 'Software'], [/android\.version$/, 'software', 'Android version'],
  [/\.creationdate$/, 'datetime', 'Created'], [/content\.identifier$/, 'tracking', 'Content identifier'], [/live-photo|still-image-time/, 'hidden', 'Live Photo link'],
  [/\.author$|\.artist$/, 'identity', 'Author'], [/\.copyright$/, 'identity', 'Copyright'], [/\.title$|\.displayname$/, 'description', 'Title'],
  [/\.description$|\.comment$/, 'description', 'Description'], [/\.keywords$/, 'description', 'Keywords'], [/\.camera\.|\.lens|capture\./, 'capture', 'Camera setting'],
  [/full-frame-rate|\.fps$/, 'capture', 'Capture frame rate'], [/aigc|ai[-_.]?generated/i, 'ai', 'AI label'],
];

function* boxes(bytes, start, end) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let i = start;
  while (i + 8 <= end) {
    let size = view.getUint32(i);
    const type = latin1.decode(bytes.subarray(i + 4, i + 8));
    let header = 8;
    if (size === 1 && i + 16 <= end) { size = Number(view.getBigUint64(i + 8)); header = 16; }
    else if (size === 0) size = end - i;
    if (size < header || i + size > end) return;
    yield { type, start: i, header, end: i + size };
    i += size;
  }
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const printable = (b) => (latin1.decode(b).match(/[\x20-\x7e\xa0-\xff]{4,}/g) || []).join(' ');

function iso6709(text, r, src) {
  const m = /([+-]\d{1,3}(?:\.\d+)?)([+-]\d{1,3}(?:\.\d+)?)([+-]\d+(?:\.\d+)?)?/.exec(text);
  if (!m) return r.field('location', 'GPS location', text, src);
  const lat = +m[1];
  const lon = +m[2];
  r.field('location', 'GPS coordinates', `${lat.toFixed(6)}, ${lon.toFixed(6)}`, src);
  if (m[3] != null) r.field('location', 'Altitude', `${round(+m[3])} m`, src);
  r.gps ??= { lat, lon, alt: m[3] != null ? +m[3] : null };
}

function qtValue(cat, name, text, r, src) {
  if (!text) return;
  if (cat === 'location' && /^[+-]\d/.test(text)) return iso6709(text, r, src);
  r.field(cat, name, text, src);
}

// Value of an iTunes/mdta item: a 'data' atom with an 8-byte type/locale prefix.
function itemValue(bytes, item) {
  for (const d of boxes(bytes, item.start + item.header, item.end)) {
    if (d.type !== 'data') continue;
    const kind = new DataView(bytes.buffer, bytes.byteOffset).getUint32(d.start + 8) & 0xffffff;
    const payload = bytes.subarray(d.start + 16, d.end);
    if (kind === 1 || kind === 4) return clean(utf8.decode(payload));
    if (kind === 2 || kind === 5) return clean((kind === 2 ? utf16be : utf16le).decode(payload));
    if (kind === 21 || kind === 22 || kind === 0) return payload.length <= 8 ? String(payload.reduce((n, b) => n * 256 + b, 0)) : printable(payload);
    return printable(payload) || `${payload.length} bytes`;
  }
  return printable(bytes.subarray(item.start + item.header, item.end));
}

function walkMeta(bytes, box, r, src) {
  // QuickTime meta has no version/flags; ISO meta does. Tell them apart by where 'hdlr' sits.
  const at = startsWith(bytes, 'hdlr', box.start + box.header + 4) ? box.start + box.header : box.start + box.header + 4;
  let keys = [];
  for (const child of boxes(bytes, at, box.end)) {
    if (child.type === 'keys') {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      keys = [];
      for (let i = child.start + 16; i + 8 <= child.end;) {
        const len = view.getUint32(i);
        if (len < 8) break;
        keys.push(latin1.decode(bytes.subarray(i + 8, i + len)));
        i += len;
      }
    } else if (child.type === 'ilst') {
      for (const item of boxes(bytes, child.start + child.header, child.end)) {
        const index = new DataView(bytes.buffer, bytes.byteOffset).getUint32(item.start + 4);
        const key = keys[index - 1];
        const value = itemValue(bytes, item);
        if (key) {
          const hit = MDTA_KEYS.find(([re]) => re.test(key));
          const label = key.replace(/^com\.(apple\.quicktime|android)\./, '');
          qtValue(hit?.[1] || 'other', hit ? (hit[2] === 'Camera setting' || hit[2] === 'Location detail' ? label : hit[2]) : label, value, r, src);
        } else {
          const [cat, name] = QT_ATOMS[item.type] || ['other', item.type.replace('©', '')];
          qtValue(cat, name, value, r, src);
        }
      }
    } else if (child.type === 'xml ' || child.type === 'XMP_') {
      parseXmp(utf8.decode(bytes.subarray(child.start + child.header + (child.type === 'xml ' ? 4 : 0), child.end)), r, `${src} XMP`);
    }
  }
}

function walkUdta(bytes, box, r, src) {
  for (const atom of boxes(bytes, box.start + box.header, box.end)) {
    const payload = bytes.subarray(atom.start + atom.header, atom.end);
    if (atom.type === 'meta') { walkMeta(bytes, atom, r, src); continue; }
    if (atom.type === 'XMP_') { parseXmp(utf8.decode(payload), r, `${src} XMP`); continue; }
    const known = QT_ATOMS[atom.type];
    let text;
    if (atom.type.charCodeAt(0) === 0xa9 && payload.length >= 4) {
      // QuickTime international text: 2-byte length, 2-byte language, then the string.
      const len = (payload[0] << 8) | payload[1];
      text = clean(utf8.decode(payload.subarray(4, 4 + len)));
    } else if (atom.type === 'loci') {
      const v = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
      const name = clean(utf8.decode(payload.subarray(6, payload.indexOf(0, 6))));
      const p = payload.indexOf(0, 6) + 2;
      if (p + 12 <= payload.length) {
        const lon = v.getInt32(p) / 65536;
        const lat = v.getInt32(p + 4) / 65536;
        r.field('location', 'GPS coordinates', `${lat.toFixed(6)}, ${lon.toFixed(6)}`, src);
        r.gps ??= { lat, lon, alt: v.getInt32(p + 8) / 65536 };
      }
      text = name;
    } else {
      text = printable(payload.subarray(['titl', 'dscp', 'auth', 'cprt', 'albm'].includes(atom.type) ? 6 : 0));
    }
    if (known) qtValue(known[0], known[1], text, r, src);
    else if (text) r.field('other', `${src} ${atom.type.trim()}`, text, src);
    else r.field('hidden', `${src} ${atom.type.trim()}`, `${payload.length} bytes of binary data`, src);
  }
}

function walkUuid(bytes, box, r) {
  const id = hex(bytes.subarray(box.start + box.header, box.start + box.header + 16));
  const body = bytes.subarray(box.start + box.header + 16, box.end);
  if (id === UUID_XMP) {
    r.block('xmp', 'XMP packet (uuid box)', box.end - box.start);
    parseXmp(utf8.decode(body), r, 'XMP');
  } else if (id === UUID_C2PA) {
    r.block('c2pa', 'C2PA Content Credentials (uuid box)', box.end - box.start, latin1.decode(body));
    parseC2pa(body, r);
  } else {
    const text = printable(body);
    r.block('uuid', `Vendor uuid box ${id.slice(0, 8)}…`, box.end - box.start, text);
    if (text) r.field('other', 'Vendor data', text, 'uuid box');
    else r.field('hidden', 'Vendor data', `${body.length} bytes of binary data`, 'uuid box');
  }
}

// mvhd / tkhd / mdhd: version byte, then creation and modification times (seconds since 1904).
function headerTimes(bytes, box) {
  const view = new DataView(bytes.buffer, bytes.byteOffset);
  const at = box.start + box.header;
  const v1 = bytes[at] === 1;
  const read = (o) => (v1 ? Number(view.getBigUint64(o)) : view.getUint32(o));
  return { at: at + 4, len: v1 ? 16 : 8, created: read(at + 4), modified: read(at + (v1 ? 12 : 8)) };
}

function walkBmff(bytes, r, start = 0, end = bytes.length, depth = 0, patch = null) {
  for (const box of boxes(bytes, start, end)) {
    if (box.type === 'ftyp' && depth === 0) {
      r.brand = latin1.decode(bytes.subarray(box.start + 8, box.start + 12));
    } else if (BMFF_CONTAINERS.has(box.type)) {
      walkBmff(bytes, r, box.start + box.header, box.end, depth + 1, patch);
    } else if (box.type === 'mvhd' || box.type === 'tkhd' || box.type === 'mdhd') {
      const t = headerTimes(bytes, box);
      if (t.created || t.modified) {
        if (box.type === 'mvhd') {
          if (t.created) r.field('datetime', 'Recorded', new Date(QT_EPOCH + t.created * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC', 'Movie header');
          if (t.modified && t.modified !== t.created) r.field('datetime', 'Modified', new Date(QT_EPOCH + t.modified * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC', 'Movie header');
        }
        r.timestamps = (r.timestamps || 0) + 1;
        patch?.push({ zero: [t.at, t.at + t.len] });
      }
    } else if (BMFF_META.has(box.type)) {
      const size = box.end - box.start;
      const where = depth === 0 ? 'file' : 'movie';
      if (box.type === 'uuid') walkUuid(bytes, box, r);
      else if (box.type === 'udta') { r.block('udta', `QuickTime user data (${where})`, size, printable(bytes.subarray(box.start, box.end))); walkUdta(bytes, box, r, 'User data'); }
      else if (box.type === 'meta') { r.block('qtmeta', `Metadata box (${where})`, size, printable(bytes.subarray(box.start, box.end))); walkMeta(bytes, box, r, 'Metadata'); }
      else { r.block('xmp', 'XMP packet', size); parseXmp(utf8.decode(bytes.subarray(box.start + box.header, box.end)), r, 'XMP'); }
      patch?.push({ free: box });
    }
  }
  if (depth === 0 && r.timestamps) r.block('timestamps', `${r.timestamps} creation / modification timestamps`, 0);
}

/** Video copy with every metadata box blanked (same size, type 'free') and header times zeroed. */
export function cleanVideo(bytes) {
  const patch = [];
  walkBmff(bytes, new Report(), 0, bytes.length, 0, patch);
  const out = bytes.slice();
  for (const p of patch) {
    if (p.zero) out.fill(0, p.zero[0], p.zero[1]);
    else {
      const { start, header, end } = p.free;
      out.set([0x66, 0x72, 0x65, 0x65], start + 4); // 'free'
      out.fill(0, start + header, end);
    }
  }
  // A trailing free box with random bytes: the file hash always changes, players ignore it.
  const tail = new Uint8Array(24);
  new DataView(tail.buffer).setUint32(0, 24);
  tail.set([0x66, 0x72, 0x65, 0x65], 4);
  crypto.getRandomValues(tail.subarray(8));
  const result = new Uint8Array(out.length + tail.length);
  result.set(out);
  result.set(tail, out.length);
  return result;
}

export function detectFormat(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xd8) return 'jpeg';
  if (startsWith(bytes, '\x89PNG')) return 'png';
  if (startsWith(bytes, 'RIFF') && startsWith(bytes, 'WEBP', 8)) return 'webp';
  if (startsWith(bytes, 'ftyp', 4)) return startsWith(bytes, 'qt  ', 8) ? 'mov' : 'mp4';
  if (['moov', 'mdat', 'wide', 'free', 'skip'].some((t) => startsWith(bytes, t, 4))) return 'mov';
  return null;
}

/**
 * Inspect a file's metadata.
 * blocks[]: container pieces that get cut out ({ kind, label, bytes }).
 * fields[]: what they contained ({ cat, name, value, src }), cat is a key of CATEGORIES.
 */
export async function inspect(bytes) {
  const r = new Report();
  const format = detectFormat(bytes);
  try {
    if (format === 'jpeg') walkJpeg(bytes, r);
    else if (format === 'png') await walkPng(bytes, r);
    else if (format === 'webp') walkWebp(bytes, r);
    else if (format === 'mp4' || format === 'mov') walkBmff(bytes, r);
  } catch (err) {
    r.field('other', 'Parse warning', `Part of the file could not be read (${err.message}); it is still removed`, 'Scanner');
  }

  const ai = AI_SIGNATURES.filter(([, re]) => re.test(r.text)).map(([name]) => name);
  const mj = /\bJob ID:\s*([0-9a-f-]{36})/i.exec(r.text)?.[1];
  if (mj) r.field('ai', 'Midjourney job ID', mj, 'Description');
  if (ai.length) r.field('ai', 'Generator detected', ai.join(', '), 'Scanner');
  const watermark = /c2pa\.watermarked/.test(r.text);

  const categories = {};
  for (const cat of CATEGORY_ORDER) {
    const n = r.fields.filter((f) => f.cat === cat).length;
    if (n) categories[cat] = n;
  }
  // Fields come out grouped by category, most sensitive first.
  r.fields.sort((a, b) => CATEGORY_ORDER.indexOf(a.cat) - CATEGORY_ORDER.indexOf(b.cat));
  return {
    format,
    blocks: r.blocks,
    fields: r.fields,
    categories,
    metaBytes: r.blocks.reduce((n, b) => n + (b.bytes || 0), 0),
    risk: riskOf(Object.keys(categories)),
    ai,
    gps: r.gps,
    watermark,
    thumbnails: r.thumbnails,
  };
}

// --- re-encode ------------------------------------------------------------
const OUTPUT = { jpeg: ['image/jpeg', 0.92, 'jpg'], png: ['image/png', undefined, 'png'], webp: ['image/webp', 0.92, 'webp'] };

function makeCanvas(w, h) {
  if (typeof OffscreenCanvas !== 'undefined') return new OffscreenCanvas(w, h);
  return Object.assign(document.createElement('canvas'), { width: w, height: h });
}

// Browser JPEG encoders add their own APP segments (Chrome embeds a "Google Inc." sRGB ICC profile).
// Keep only JFIF (APP0); sRGB is the default when no profile is present.
function stripJpegApps(bytes) {
  const keep = [bytes.subarray(0, 2)];
  let i = 2;
  while (i + 4 <= bytes.length && bytes[i] === 0xff) {
    const marker = bytes[i + 1];
    if (marker === 0xda) break;
    const end = i + 2 + ((bytes[i + 2] << 8) | bytes[i + 3]);
    if (!((marker >= 0xe1 && marker <= 0xef) || marker === 0xfe)) keep.push(bytes.subarray(i, end));
    i = end;
  }
  keep.push(bytes.subarray(i));
  return new Blob(keep, { type: 'image/jpeg' });
}

// Same for WebP: Chrome writes an ICCP chunk. Drop ICCP/EXIF/XMP, clear their VP8X flag bits, fix the RIFF size.
function stripWebpChunks(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keep = [];
  let i = 12;
  while (i + 8 <= bytes.length) {
    const type = latin1.decode(bytes.subarray(i, i + 4));
    const len = view.getUint32(i + 4, true);
    const end = Math.min(bytes.length, i + 8 + len + (len & 1));
    if (!['ICCP', 'EXIF', 'XMP '].includes(type)) {
      const chunk = bytes.slice(i, end);
      if (type === 'VP8X') chunk[8] &= ~(0x20 | 0x08 | 0x04); // ICC, EXIF, XMP flags
      keep.push(chunk);
    }
    i = end;
  }
  const size = keep.reduce((n, c) => n + c.length, 4);
  const header = new Uint8Array(12);
  header.set(bytes.subarray(0, 12));
  new DataView(header.buffer).setUint32(4, size, true);
  return new Blob([header, ...keep], { type: 'image/webp' });
}

async function toBlob(canvas, type, quality) {
  const blob = canvas.convertToBlob
    ? await canvas.convertToBlob({ type, quality })
    : await new Promise((ok, fail) => canvas.toBlob((b) => (b ? ok(b) : fail(new Error('Encoding failed'))), type, quality));
  if (blob.type === 'image/jpeg') return stripJpegApps(new Uint8Array(await blob.arrayBuffer()));
  if (blob.type === 'image/webp') return stripWebpChunks(new Uint8Array(await blob.arrayBuffer()));
  return blob;
}

export async function sha256(buf) {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Decode → draw → re-encode. Bakes in EXIF orientation, drops every metadata block. */
export async function reencode(file, format, hashBefore) {
  const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
  const { width, height } = bitmap;
  const canvas = makeCanvas(width, height);
  const ctx = canvas.getContext('2d');
  let [type, quality, ext] = OUTPUT[format] || OUTPUT.jpeg;
  if (type === 'image/jpeg') { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, width, height); }
  ctx.drawImage(bitmap, 0, 0);

  let blob = await toBlob(canvas, type, quality);
  // Some browsers (older Safari) silently fall back to PNG for WebP.
  if (blob.type !== type) { type = blob.type; ext = type === 'image/png' ? 'png' : 'jpg'; }
  let buf = new Uint8Array(await blob.arrayBuffer());
  let hash = await sha256(buf);

  // Lossless round-trips can reproduce identical bytes; nudge one pixel so the hash always changes.
  if (hash === hashBefore) {
    const px = ctx.getImageData(0, 0, 1, 1);
    px.data[0] ^= 1;
    ctx.putImageData(px, 0, 0);
    blob = await toBlob(canvas, type, quality);
    buf = new Uint8Array(await blob.arrayBuffer());
    hash = await sha256(buf);
  }

  return { blob, bytes: buf, hash, width, height, type, ext, bitmap };
}
