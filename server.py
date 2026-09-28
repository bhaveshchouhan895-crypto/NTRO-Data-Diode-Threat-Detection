import shutil
import os
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from engine import analyze_pcap_file

app = FastAPI(title="NTRO Threat Ingestion API")

# Frontend (HTML/JS) ke sath connection allow karne ke liye
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "temp_pcaps"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/api/upload-pcap")
async def process_pcap(file: UploadFile = File(...)):
    """PCAP file ko receive karke AI model se scan karwata hai."""
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    threats = analyze_pcap_file(file_path)

    # Process hone ke baad temporary file delete karna
    try:
        os.remove(file_path)
    except:
        pass

    return {
        "status": "success",
        "threats_detected": len(threats),
        "incidents": threats
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)