# The unknown city

**Author:** Incendio

---

### Challenge Description
>
> Vice City has its own rules. Money talks, loyalty is temporary, and every deal leaves a trace.
> 
> Somewhere in the middle of all the chaos, a photograph surfaced. It doesn't look like much, but in this city, even the smallest details can lead you somewhere you weren't supposed to be.
> 
> Find the truth. Just remember: in Vice City, nobody gives anything away for free.
>

Flag format: Securinets{location_name}


The challenge provides a **normal-looking image**.

---

### Solution

1. Start by inspecting the image's metadata using `exiftool`:

   ```bash
   exiftool evidence.jpg
   ```

2. Review the output carefully and look for GPS-related fields, including `GPSLatitude` and `GPSLongitude`.

3. The image contains the following coordinates:

   ```text
   GPS Latitude                    : 25 deg 46' 54.48" N
   GPS Longitude                   : 80 deg 8' 6.72" W
   GPS Position                    : 25 deg 46' 54.48" N, 80 deg 8' 6.72" W

   ```

4. Enter the coordinates into this site so you can use it in google maps

   ```text
   https://geratools.com/dms-to-lat-lng
   ```

   This will give you this coordinates to use in google maps

   ```text
   25.781800, -80.135200
   ```

5. The coordinates lead to **Miami Beach, Florida, USA**, the real-world setting that inspired the atmosphere of Vice City.

6. Submit the city name in the expected flag format:

   ```text
   Securinets_fst{miami_beach}
   ```

---

### Key Takeaway

This challenge demonstrates how seemingly ordinary images can retain valuable location information in their EXIF metadata. Using `exiftool` to inspect GPS coordinates and Google Maps to investigate them is a simple but effective combination of digital forensics and OSINT.

Sometimes, the smallest trace is enough to expose the whole scene.
