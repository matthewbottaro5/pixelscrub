# PixelScrub cleaner

The code that reads and removes metadata on [pixelscrub.com](https://pixelscrub.com). It runs entirely in the browser: photos and videos are never uploaded.

This repository is published so anyone can check what the site does with their files.

## What's here

| File | What it does |
|------|--------------|
| `src/scrub.js` | Parses JPEG segments, PNG and WebP chunks, and MP4/MOV boxes. Decodes EXIF, GPS, XMP, IPTC, ICC, C2PA and AI-generator metadata. Re-encodes photos from pixels, and blanks metadata boxes in videos in place, without re-encoding. Re-scans every result. |
| `src/categories.js` | Sorts each field into a category (location, device, people, AI…) and scores privacy risk. |
| `src/app.js` | The page logic: file handling, the report, downloads, `sendSummary` (the per-file summary) and `track` (usage events). |
| `src/zip.js` | Builds the "download all" ZIP in the browser. |

## What the site sends

`sendSummary` in `src/app.js` sends one small JSON summary per cleaned file:

- how many fields of each category were removed (for example `{"location": 1, "device": 2}`), never their values;
- container kinds and sizes (for example `exif`, 320 bytes);
- the AI generator's name if one was detected (for example "Midjourney"), never prompts;
- file type, size, pixel dimensions, risk score, cleaning time, and whether location was present.

No file, preview, file name, hash, coordinates or field values are sent. The server also drops those fields if they arrive, and stores the summary without IP address or visitor ID, with its time rounded to the hour. 

`track` in `src/app.js` also sends usage events: a page view (the referring site, screen size, browser time zone, and whether the browser reports automation, used to filter out bots), the first mouse, touch or key interaction, download and ZIP counts without file names, and errors. Like any website, the server logs IP addresses for page requests; see the [Terms](https://pixelscrub.com/terms).

## How cleaning works

- **Photos (JPEG, PNG, WebP):** the image is decoded to pixels, with orientation applied, and encoded into a new file. Nothing from the original container is copied. The result is scanned again, and the SHA-256 before and after is shown.
- **Videos (MP4, MOV):** metadata boxes (`udta`, `meta`, `uuid`/C2PA and `XMP_`, which hold location, device, dates and AI labels) are overwritten in place, and creation and modification times in the movie and track headers are cleared, so every sample offset stays valid and the audio and video streams are copied byte for byte. A small random `free` box is added so the hash changes.

## License

MIT. See `LICENSE`.
