"""Generate a dark, minimal electronic soundtrack for the SecureMailScope brag video."""
import struct, wave, math, os

RATE = 44100
DUR = 20.0
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audio.wav")

def gen():
    frames = []
    for i in range(int(RATE * DUR)):
        t = i / RATE

        # ── Master envelope (fade in / fade out) ──
        env = 1.0
        if t < 1.5:
            env = t / 1.5
        elif t > 18.0:
            env = max(0, (20.0 - t) / 2.0)

        # ── Sub-bass drone: stacked fifths ──
        bass = (
            0.12 * math.sin(2 * math.pi * 55 * t) +
            0.07 * math.sin(2 * math.pi * 82.5 * t) +
            0.04 * math.sin(2 * math.pi * 110 * t)
        )

        # ── Slow LFO modulation on the bass ──
        lfo = 0.85 + 0.15 * math.sin(2 * math.pi * 0.15 * t)
        bass *= lfo

        # ── High shimmer pad (very subtle) ──
        shimmer = 0.015 * math.sin(2 * math.pi * 440 * t + 0.5 * math.sin(2 * math.pi * 0.3 * t))
        shimmer += 0.01 * math.sin(2 * math.pi * 554.37 * t)  # C#5

        # ── Scene transition hits ──
        hit = 0.0
        for ht in [3.0, 7.8, 14.8]:
            if ht <= t < ht + 0.15:
                h_env = math.exp(-20 * (t - ht))
                hit += 0.08 * h_env * math.sin(2 * math.pi * 80 * t)

        # ── Warning tone at critical finding (5.2s) ──
        warning = 0.0
        if 5.15 < t < 6.0:
            w_env = math.exp(-4.0 * (t - 5.15))
            warning = 0.06 * w_env * math.sin(2 * math.pi * 392 * t)  # G4
            warning += 0.03 * w_env * math.sin(2 * math.pi * 466.16 * t)  # Bb4 (minor feel)

        # ── Resolution chord at outro (15.0s) ──
        reso = 0.0
        if 15.0 < t < 19.5:
            r_in = min(1, (t - 15.0) / 0.8)
            r_out = 1 - max(0, (t - 18.5) / 1.0)
            r_env = r_in * r_out
            reso = 0.03 * r_env * (
                math.sin(2 * math.pi * 146.83 * t) +   # D3
                math.sin(2 * math.pi * 220 * t) +       # A3
                math.sin(2 * math.pi * 293.66 * t) +    # D4
                0.5 * math.sin(2 * math.pi * 369.99 * t) # F#4
            )

        # ── Mix ──
        sample = (bass + shimmer + hit + warning + reso) * env
        sample = max(-0.95, min(0.95, sample))

        val = int(sample * 32767)
        frames.append(struct.pack('<hh', val, val))  # stereo

    with wave.open(OUT, 'w') as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
    print(f"Audio written to {OUT}")

if __name__ == "__main__":
    gen()
