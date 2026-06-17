# BeaconButty demo — contributor guide

## What this project is

A standalone Flask demo of the BeaconButty network beacon detector. No production
dependencies (no Zeek / RITA / ClickHouse / Suricata / live packet capture). Every page
renders fixtures from `demo_data.py`. Intended for conference talks and training.

Production lives at https://github.com/mustard-research/BeaconButty (and locally on bb0
at `/home/dm/BeaconButty/`). This repo is completely independent — no shared code, no
shared deployment, no runtime dependencies on the production system.

## File inventory

| File | Purpose |
|------|---------|
| `app.py` | Flask route handlers. ~300 lines. Each page route is `render_template("foo.html", **demo_data.PAGE)`; each mutator returns a success stub. |
| `demo_data.py` | All fixture data. ~1500 lines. Edit here to customise the demo narrative. Timestamps derive from a fixed `REF_DT` so output is deterministic. |
| `templates/` | Jinja templates **copied verbatim from production**. Do not edit them here — see "Keeping templates in sync" below. |
| `static/` | CSS + logo assets, copied verbatim from production. |
| `systemd/beaconbutty-demo.service` | Single systemd unit. Installed to `/etc/systemd/system/` by `install.sh` / `bootstrap.sh`. |
| `bootstrap.sh` | Fresh-Pi one-shot installer (curl-pipe-friendly). |
| `install.sh` | Local installer (run after `git clone`). |
| `requirements.txt` | Just `flask`. Informational — installed via apt's `python3-flask`. |

## Principles (in priority order)

1. **No production dependencies.** Never import anything that requires a system package
   beyond Flask + the Python stdlib. No `subprocess`, no `/var/lib/beaconbutty/` file reads,
   no network calls, no `clickhouse-client`. If a feature would require a production
   dependency to demo authentically, fake it with a fixture.

2. **Templates are read-only.** They are verbatim copies from production
   (`/home/dm/BeaconButty/webapp/templates/`). The only sanctioned demo-specific change is
   the demo-mode banner block in `base.html`. Any other template change must land in
   production first, then be copied across.

3. **All customisation goes in `demo_data.py`.** Anyone retelling the demo for a different
   story (different beacon scores, different threat hits, different device names) should
   only need to edit this file.

4. **Mutators stay stubbed.** FP add/remove, rule toggle, backup run, Slack clear, Teams
   threshold edit — none of them must ever do anything. They return JSON success or
   redirect-with-flash. The DEMO MODE banner in `base.html` makes this transparent.

5. **Deterministic output.** No `datetime.now()` anywhere in `demo_data.py`. Use the
   `REF_DT` constant; derive all other timestamps from it.

## Keeping templates in sync with production

When the production webapp templates change (which happens often), the demo's templates
must be re-synced. The procedure:

```sh
# 1. Copy all production templates over, replacing demo's copies
cp -r /home/dm/BeaconButty/webapp/templates/* templates/

# 2. Re-add the demo-mode banner block to base.html (the only sanctioned diff)
#    Look for the block right after <body> — see git history for the exact form.

# 3. Smoke-test that every page still renders
cd /home/dm/beaconbutty-demo
PORT=5001 python3 app.py &
sleep 2
for p in / /system /bandwidth /beacons /beacons/slow /suricata /suricata/rules /network /assets /fps /health /backup; do
  printf '%s  %s\n' "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:5001$p)" "$p"
done
kill %1

# 4. If anything 500s, the template now references a new variable.
#    Find the missing variable in the template, add it to demo_data.py.
```

## Common tasks

**Change a beacon score, device name, or destination:**
Edit `demo_data.py` → `BEACONS['beacon_data']['devices']` and `top_beacons` / `investigate`.

**Add a new threat finding to the headline narrative:**
Hits on Network Intel? Edit `NETWORK_INTEL['ja4_threats']`. A new Suricata signature?
`SURICATA['sig_list']` and the corresponding `lan_rows` entry. A new false-positive case
study? `FPS['rows']`. A new Teams-relay finding? `TEAMS_DETECTOR_REPORT['findings']`.

**Update for a production template change:**
1. Copy the new template over (see "Keeping templates in sync" above).
2. Grep the new template for any `{{ new_var }}` or `{% for x in new_var %}` references.
3. Add the new variable to the relevant section in `demo_data.py`.
4. If the production app passes the variable from a new route, mirror that route in
   `app.py` (page route or `/api/...` endpoint).

**Add a new mutator endpoint to match production:**
Add it to `app.py` and route through `_stub_ok(...)` (for JSON endpoints) or
`_stub_redirect_back(...)` (for form-redirect endpoints). It must not touch any state.

## Anti-patterns to avoid

- Adding `subprocess.run()` or any system-level command.
- Adding `with open('/var/...')` or any path outside the repo's own tree.
- Editing a template to "make the demo look better" — change the fixture instead.
- Using `datetime.now()` or `time.time()` in `demo_data.py` (breaks determinism;
  screenshots taken months apart should look identical).
- Adding a Python package outside `requirements.txt` that isn't in the Pi OS Lite
  default install or Bookworm's `python3-flask` apt package.
