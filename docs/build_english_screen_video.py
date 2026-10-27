"""Build a FlowTwin walkthrough with English slides and expanded Hindi narration.

Optional authoring dependencies:
    python -m pip install playwright edge-tts imageio-ffmpeg
Microsoft Edge is used for slide rendering. Hindi narration requires internet.
"""

import asyncio
import base64
import html
import re
import subprocess
import tempfile
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "screenshots"
OUTPUT = ROOT / "docs" / "flowtwin-demo-english-screen-hindi-voice.mp4"
TRANSCRIPT = ROOT / "docs" / "hindi-demo-script.md"
COVER = SHOTS / "flowtwin-english-screen-video-cover.png"
VOICE = "hi-IN-SwaraNeural"
NARRATION_LABEL = "Hindi"

from video_english_content import SEGMENTS

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def duration_of(path, ffmpeg):
    result = subprocess.run([ffmpeg, "-hide_banner", "-i", str(path), "-f", "null", "-"], capture_output=True, text=True, errors="replace")
    match = re.search(r"Duration:\s*(\d+):(\d+):(\d+\.\d+)", result.stderr)
    if not match:
        raise RuntimeError(f"Could not measure audio: {path}\n{result.stderr[-600:]}")
    hours, minutes, seconds = match.groups()
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def slide_html(segment, number):
    image_path = SHOTS / segment["image"]
    image_data = base64.b64encode(image_path.read_bytes()).decode("ascii")
    points = "".join(f"<li>{html.escape(point)}</li>" for point in segment["points"])
    note = html.escape(segment["note"])
    offset = segment["offset"]
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><style>
      *{{box-sizing:border-box}}body{{margin:0;width:1280px;height:720px;overflow:hidden;background:radial-gradient(circle at 82% 2%,#164447 0%,#0c1d30 34%,#080e19 76%);color:#e8f5fa;font-family:'Segoe UI',Arial,sans-serif}}
      .frame{{width:1280px;height:720px;padding:38px 43px;display:flex;flex-direction:column}}
      header{{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #315066;padding-bottom:19px;font-size:16px;color:#8ccfcf}}
      .brand{{font-size:28px;font-weight:750;letter-spacing:-1px;color:#f2ffff}}.brand span{{color:#39d7c5}}
      .stage{{display:flex;gap:34px;align-items:center;flex:1}}
      .copy{{width:42%;padding-right:8px}}.eyebrow{{color:#51cbbf;font-size:15px;font-weight:700;letter-spacing:1.4px;margin-bottom:15px}}
      h1{{font-size:36px;line-height:1.18;margin:0 0 23px;font-weight:730;color:#f5fbff}}
      ul{{list-style:none;padding:0;margin:0;display:grid;gap:12px}}li{{font-size:19px;line-height:1.35;padding:12px 14px 12px 18px;border-left:4px solid #44d9c9;background:#1431429c;border-radius:0 10px 10px 0;color:#d4e6ed}}
      .note{{font-size:15px;line-height:1.45;color:#95bdc8;margin-top:20px;padding-left:4px}}
      .screen{{width:58%;height:527px;overflow:hidden;position:relative;border:1px solid #426779;border-radius:15px;box-shadow:0 25px 75px #0009;background:#0b1422}}
      .screen img{{display:block;width:100%;height:auto;transform:translateY(-{offset}px)}}
      footer{{border-top:1px solid #315066;padding-top:14px;color:#91a8b6;font-size:14px;display:flex;justify-content:space-between}}
      </style><div class="frame"><header><div class="brand">Flow<span>Twin</span></div><div>PROJECT WALKTHROUGH · {NARRATION_LABEL.upper()} VOICEOVER</div></header>
      <div class="stage"><div class="copy"><div class="eyebrow">CHAPTER {number:02d} / {len(SEGMENTS):02d}</div><h1>{html.escape(segment['title'])}</h1><ul>{points}</ul><p class="note">{note}</p></div>
      <div class="screen"><img src="data:image/png;base64,{image_data}"></div></div>
      <footer><span>Computer Networks + Machine Learning</span><span>REAL APPLICATION SCREENS · EDUCATIONAL DEMO</span></footer></div></html>"""


async def render_audio(segments, work):
    for index, segment in enumerate(segments):
        await edge_tts.Communicate(segment["speech"], VOICE, rate="-4%").save(str(work / f"audio-{index:02d}.mp3"))


def main():
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    transcript = [f"# FlowTwin demo: English on-screen text, {NARRATION_LABEL} narration", "", f"The video uses real application screenshots and expanded {NARRATION_LABEL} voiceover. The spoken script follows each English chapter title.", ""]
    for index, segment in enumerate(SEGMENTS, 1):
        transcript.extend([f"## {index}. {segment['title']}", "", segment["speech"], ""])
    TRANSCRIPT.write_text("\n".join(transcript), encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="flowtwin-video-") as temp_dir:
        work = Path(temp_dir)
        asyncio.run(render_audio(SEGMENTS, work))
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 720}, device_scale_factor=1)
            for index, segment in enumerate(SEGMENTS):
                page.set_content(slide_html(segment, index + 1), wait_until="load")
                page.screenshot(path=str(work / f"slide-{index:02d}.png"))
                if index == 0:
                    page.screenshot(path=str(COVER))
            browser.close()
        clips = []
        for index in range(len(SEGMENTS)):
            audio = work / f"audio-{index:02d}.mp3"
            slide = work / f"slide-{index:02d}.png"
            clip = work / f"clip-{index:02d}.mp4"
            seconds = duration_of(audio, ffmpeg) + 0.5
            fade_start = max(0, seconds - 0.45)
            run(ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-loop", "1", "-framerate", "25", "-i", str(slide), "-i", str(audio), "-vf", f"fade=t=in:st=0:d=0.25,fade=t=out:st={fade_start:.2f}:d=0.45", "-af", "apad=pad_dur=0.5", "-t", f"{seconds:.2f}", "-c:v", "libx264", "-preset", "veryfast", "-crf", "22", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "48000", str(clip))
            clips.append(clip)
            print(f"Rendered segment {index + 1}/{len(SEGMENTS)} ({seconds:.1f}s)", flush=True)
        concat_file = work / "clips.txt"
        concat_file.write_text("\n".join(f"file '{clip.as_posix()}'" for clip in clips), encoding="utf-8")
        run(ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat_file), "-c", "copy", "-movflags", "+faststart", str(OUTPUT))
        print(f"Created {OUTPUT} ({OUTPUT.stat().st_size / 1_000_000:.1f} MB)")


if __name__ == "__main__":
    main()
