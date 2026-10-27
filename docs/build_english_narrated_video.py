"""Build the fully English FlowTwin teacher demo from the same application slides."""

import build_english_screen_video as base
from video_english_content import ENGLISH_SPEECHES

assert len(ENGLISH_SPEECHES) == len(base.SEGMENTS)
base.SEGMENTS = [dict(segment, speech=speech) for segment, speech in zip(base.SEGMENTS, ENGLISH_SPEECHES)]
base.OUTPUT = base.ROOT / "docs" / "flowtwin-demo-english.mp4"
base.TRANSCRIPT = base.ROOT / "docs" / "english-demo-script.md"
base.COVER = base.SHOTS / "flowtwin-english-video-cover.png"
base.VOICE = "en-IN-NeerjaNeural"
base.NARRATION_LABEL = "English"


if __name__ == "__main__":
    base.main()
