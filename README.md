# Canon Card Importer

A small Windows app that automatically copies photos and videos from a Canon EOS SD card into daily folders (`YYYY_MM_DD`) on your computer, skipping duplicates.  
Built with Python + Tkinter, packaged into a standalone `.exe`.

---

## Why this exists

My Canon EOS 700D’s USB port rusted badly and stopped working, so the camera could no longer be detected over USB. Canon’s EOS Utility software became useless for me.
  
Instead of paying for a repair, I asked ChatGPT to help me write code for a simple EOS Utility importer tool clone that works directly with a card reader and a SD card.  

This project is the result.  

---

## Features
- Source folder = your SD card (handles multiple `DCIM/100CANON`, `101CANON`, etc).  
- Destination folder = your photo archive, auto-organized into daily folders.  
- Duplicate detection (size and optional file hash).  
- Two progress bars (overall + per file).  
- Log file written to destination.  
- Remembers your last source/destination.  
- Works without Canon EOS Utility.

---

## Usage
1. Insert your Canon SD card with a card reader.  
2. Launch the app.  
3. Choose Source (SD card) and Destination (your photo storage).  
4. Click **Dry Run** to preview or **Start Import** to copy.  
5. Photos will appear in `YYYY_MM_DD` folders.

---

## Building from source
```powershell
py -m pip install exifread
py CanonImporter_tk.py

