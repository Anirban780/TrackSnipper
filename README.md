# TrackSnipper

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-username/tracksnipper/ci.yml?branch=main)](https://github.com/your-username/tracksnipper/actions)
[![PyPI Version](https://img.shields.io/pypi/v/tracksnipper)](https://pypi.org/project/tracksnipper)
[![License](https://img.shields.io/github/license/your-username/tracksnipper)](LICENSE)

A lightweight **CLI** tool written in **Python** for **Linux** systems to detect, classify, and log suspicious activity by parsing system logs, storing events in **SQLite**, and generating comprehensive security reports.

---

## 🚀 Features

* 🔍 **Log Parsing**: Scan `/var/log/auth.log` and `/var/log/syslog` for anomalous events
* 📊 **Incident Detection**: Identify repeated failed SSH logins, unauthorized `sudo` usage, new user sessions, and more
* 💾 **SQLite Storage**: Persist structured `Incident` records with timestamps, categories, and severity levels
* 📑 **Reporting**: Export summaries in **text**, **JSON**, **CSV**, or **HTML** formats
* 🖥️ **Real‑Time Mode**: Tail logs continuously with `--watch` flag (planned)
* 📦 **Installable**: Available via `pip install tracksnipper` with `console_scripts` entry point
* 🔧 **Modular Architecture**: Easily extend detection rules, storage backends, and report formats
* ✅ **Tested & CI‑Ready**: Unit tests with **pytest** and CI pipeline via GitHub Actions

---

## 💾 Installation

> Requires Python 3.10+ on a Linux environment

```bash
# From PyPI
pip install tracksnipper

# Or from source
git clone https://github.com/Anirban780/tracksnipper.git
cd tracksnipper
pip install -e .
```

---

## 🛠️ Quickstart

1. **Scan logs** and populate the database:

   ```bash
   tracksnipper scan --log auth
   tracksnipper scan --log syslog
   ```

2. **View recorded incidents**:

   ```bash
   tracksnipper list --severity high
   ```

3. **Generate a report** in JSON or text:

   ```bash
   tracksnipper report --format json --output reports/incidents.json
   ```

4. **Watch live** (beta):

   ```bash
   tracksnipper scan --log auth --watch
   ```

---

## ⚙️ Configuration

By default, TrackSnipper uses built‑in thresholds. To customize, create a `tracksnipper.yml` in your home directory:

```yaml
log_paths:
  auth: /var/log/auth.log
  syslog: /var/log/syslog
thresholds:
  ssh_failures: 5        # max failures per minute
  sudo_events: 3         # max sudo uses per hour
severity_map:
  low: ["new-session"]
  medium: ["sudo-usage"]
  high: ["ssh-bruteforce"]
```

---

## 🧪 Testing & CI

```bash
# Run unit tests
pytest --cov
```

CI is configured in `.github/workflows/ci.yml` to run on every push and PR, including linting via **flake8** and tests on Python 3.10/3.11.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: \`git commit -m "feat: Add my-feature"
4. Push branch: `git push origin feature/my-feature`
5. Open a Pull Request against `main`

Please abide by the [code of conduct](CODE_OF_CONDUCT.md).

---

## 📖 Roadmap

* [x] Core parser for `auth.log` & `syslog`
* [x] SQLite persistence layer
* [x] CLI commands: `scan`, `list`, `report`
* [ ] Real‑time watch mode
* [ ] Email/SMS alert integration
* [ ] Web dashboard (Flask/Streamlit)

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

[Anirban](https://github.com/Anirban780)  [Email](fairytailanirbans@gmail.com)
