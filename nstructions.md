Build a jaw-dropping, cinematic 3D landing page for "Hybrid R-Sentry" — 
an AI-powered ransomware detection system. This should feel like a 
cybersecurity product from 2035. Every section must have motion, depth, 
and visual drama. Use React Three Fiber + Drei + Framer Motion + Tailwind.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GLOBAL DESIGN LANGUAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Background: pure #000005 (near black with blue undertone)
- Primary glow: electric cyan #00f5ff
- Threat color: blood red #ff1744
- AI color: violet #b537f2
- Safe color: matrix green #00ff88
- Font: "Space Grotesk" for headings, "JetBrains Mono" for code/data
- Everything has depth: layered blur, glow halos, light bloom effects
- Cursor: custom crosshair that glows cyan on hover
- Subtle animated grid lines across entire page (like a radar screen)
- Floating scan lines overlay the whole page at 3% opacity

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 1 — CINEMATIC HERO
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full viewport height. No scroll needed to see everything important.

3D CENTERPIECE (React Three Fiber canvas, full background):
- A slowly rotating Earth-like sphere built entirely from glowing NODE DOTS
  connected by thin cyan edge lines — this IS the filesystem graph
- Nodes pulse red when "threat detected" animation fires every 4 seconds
- Infected nodes spread red glow outward along edges like a virus propagating
- Then cyan nodes (containment) chase the red and extinguish it
- 2000+ floating particles orbit the sphere like an atmosphere
- Subtle volumetric fog around the sphere base
- The sphere casts a cyan light bloom onto the dark background below it

FOREGROUND TEXT (centered, above the 3D canvas):
- Small badge top: "FINAL YEAR PROJECT · KALI LINUX 2024" in mono font 
  with a blinking green dot
- H1: "HYBRID R-SENTRY" — massive, bold, white with cyan text-shadow glow
  Each letter animates in with a glitch effect on page load
- H2: "Ransomware dies here." — italic, violet, fades in after H1
- Body: "The only detection system that sees ransomware before it 
  touches your files — using entropy physics, process DNA, and 
  self-repositioning AI canaries."
- Two CTA buttons side by side:
  [▶ Watch Demo] — solid cyan fill, black text, 3D press effect on click
  [< > GitHub] — outline only, cyan border, glows brighter on hover
- Below buttons: live-looking stats counter that animates up on load:
  "12ms avg detection · 0 false positives · 4 detection layers · 100% containment"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 2 — THE THREAT TIMELINE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "From First Byte to Full Containment"
Subtitle: "Four detection layers fire in parallel. Ransomware has nowhere to hide."

A horizontal 3D pipeline — looks like a glowing circuit board traced left to right.
Each node is a glowing hexagon that rises up from the surface on scroll:

[🔴 FILE WRITE] ──▶ [📊 ENTROPY ENGINE] ──▶ [🧬 LINEAGE SCORER]
                              ↓                         ↓
                    [⚡ COMBINED SCORE] ──▶ [🔒 SIGSTOP PIPELINE]
                              ↓
                    [🤖 POWERFUL AI ANALYST] ──▶ [📡 LIVE DASHBOARD]

- Each hexagon has a number badge showing latency: "< 2ms", "< 5ms", etc.
- Connecting lines animate with a traveling pulse of light (like data flowing)
- On hover each node expands into a floating card with details
- The SIGSTOP node is blood red and shakes slightly — maximum threat energy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 3 — 4 ENHANCEMENT PILLARS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "Four Enhancements. One Unbreakable Shield."

Four massive 3D cards in a 2×2 grid. Each card:
- Has a unique 3D icon rotating slowly inside it (Three.js geometry)
- Floats 20px above the grid with a colored shadow beneath it
- On hover: rises another 30px, rotates slightly, inner light blooms brighter
- Background: glassmorphism (frosted dark glass, colored border glow)

CARD 1 — ENTROPY VELOCITY PROFILING [gold glow]
  Icon: rotating waveform / oscilloscope geometry
  "Shannon entropy computed across all directories simultaneously.
   When 3+ directories spike together within 10 seconds — ransomware
   is encrypting in bulk. EVP catches what signatures miss."
  Mini chart: animated entropy curve with threshold line blinking red

CARD 2 — PROCESS LINEAGE SCORING [violet glow]
  Icon: rotating DNA double-helix built from small spheres
  "Every process has a family tree. We score its entire ancestry —
   parent names, spawn location, binary SHA-256 hash.
   A process born in /tmp with no TTY scores 80/100 immediately."
  Mini badge row: [/tmp/ +50] [Unknown hash +25] [No TTY +5]

CARD 3 — ADAPTIVE CANARY REPOSITIONING [cyan glow]
  Icon: rotating Markov chain graph (nodes + directed edges)
  "15 AAA_ canary files move themselves. A Markov transition matrix
   learns the ransomware's traversal pattern and predicts its next
   directory — placing a canary there before it arrives."
  Live counter animating: "Prediction confidence: 87%"

CARD 4 — SIGSTOP CONTAINMENT [red glow]
  Icon: rotating padlock that slams shut on hover
  "Four steps. No escape. SIGSTOP freezes execution → /proc forensics
   captured → iptables cuts all network traffic → SIGKILL ends the
   process. Total time: under 200ms."
  Step badges glowing in sequence: [FREEZE] → [CAPTURE] → [BLOCK] → [KILL]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 4 — LIVE THREAT CONSOLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "The Dashboard That Never Blinks"
Full-width dark terminal mockup that looks like the real React dashboard:

Left panel — ALERT FEED (simulated, auto-scrolling):
New alerts appear every 2-3 seconds with realistic fake data:
  🔴 CRITICAL  CANARY_TOUCHED  /home/user/Documents/AAA_a3f9.txt  pid:4721
  🟠 HIGH      COMBINED_ALERT  /home/user/Downloads/invoice.pdf   pid:3847
  🟡 MEDIUM    ENTROPY_SPIKE   /home/user/Desktop/report.docx     pid:2291
  🤖 AI AUTO-ACK → Powerful AI identified benign process. Alert resolved.

Right panel — RISK GAUGE:
Animated radial gauge sweeping from 0 → 87 in red, then dropping back to
12 in green after "containment complete" event fires

Bottom bar — 3 live stat counters ticking up:
  Files Scanned: 847,291  |  Threats Stopped: 23  |  Uptime: 99.97%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 5 — TECH STACK UNIVERSE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "Built on Battle-Tested Technology"

3D solar system layout — technologies orbit a central "R-Sentry" core:
- Center: glowing R-Sentry logo sphere
- Inner orbit: Python, FastAPI, React (fast orbit)
- Middle orbit: PostgreSQL, Redis, Celery, Docker (medium orbit)
- Outer orbit: NetworkX, NumPy, psutil, SciPy, Advanced AI LLM (slow orbit)

Each planet is a glowing sphere with the tech name as a text label.
Clicking a planet pops up a floating card explaining what that tech does
in the system. The "Advanced AI LLM" planet pulses violet and is the
largest outer planet — representing the most powerful analytical layer.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 6 — ARCHITECTURE DIAGRAM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "System Architecture"
Interactive 3D node graph showing the 5 layers:

[KALI AGENT] → [FASTAPI BACKEND] → [CELERY WORKERS] → [POWERFUL AI]
     ↓                ↓                    ↓
[WATCHDOG]      [POSTGRESQL]          [REDIS PUB/SUB]
     ↓                                    ↓
[CONTAINMENT]                      [REACT DASHBOARD]

Nodes are 3D boxes with glowing edges. Animated data packets (small
glowing spheres) travel along the connection lines continuously.
On hover each node shows its role description in a tooltip.
The AI node is the largest, glows violet, and pulses with a heartbeat
animation — it is the brain of the entire system.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 7 — TEAM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title: "The Team Behind the Shield"
4 holographic team cards in a row. Each card:
- Frosted glass background with member color accent
- Floating member number badge (M1, M2, M3, M4)
- Role title in large font
- Ownership list with glowing bullet points
- On hover: card flips in 3D to show tech stack used

M1 — Mohammad Hudib    [red]    Endpoint Agent
                                watchdog · inotify · SIGSTOP pipeline
M2 — Mahmoud Hussein   [gold]   Graph & EVP Engine
                                networkx · scipy · canary placement
M3 — Ahmad Jehad       [cyan]   Backend & Dashboard
                                FastAPI · PostgreSQL · Redis · React
M4 — Adnan Alshrouqi   [violet] Detection & Testing
                                lineage scoring · adaptive repositioning
                                simulation scripts · pytest

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECTION 8 — FINAL CTA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Full viewport dark section with the 3D sphere from the hero (smaller)
floating in the background.

Center text:
"Ransomware encrypted files while you read this page.
 Hybrid R-Sentry would have stopped it in 12ms."

Two buttons: [⭐ Star on GitHub]  [📄 Read the Paper]

Footer: "Hybrid R-Sentry · Built on R-Sentry by Hussain, Faghihi et al.
· Kali Linux 2024 · Python 3.11"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PERFORMANCE REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- Use InstancedMesh for all particle systems (never individual meshes)
- Lazy-load Three.js canvas sections (only render when in viewport)
- All scroll animations via Framer Motion useInView
- 60fps target on a mid-range laptop
- Mobile: reduce particle count to 200, disable bloom and fog,
  halve geometry complexity
- Pure frontend only — no backend needed
- All live stats and alert feed simulated with useState and setInterval