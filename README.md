# 🔍 AutoRecon-Bash

Simple bash-based recon tool for subdomain enumeration, port scanning, dir brute-forcing, and CVE lookup.

---

## 🚀 Features

- Subdomain enumeration (`assetfinder`)
- Live check (`curl`)
- Port scanning (`nmap`)
- Directory brute-forcing (`ffuf`)
- CVE lookup (`searchsploit`)
- Smart 403 filtering + colored output
- Organized reports in `output/` folder

---

## 📦 Setup

```bash
git clone https://github.com/6cloudguy/recon-scanner.git
cd recon-scanner
chmod +x *.sh
./install_reqs.sh
```

---

## 🔧 Usage

```bash
./recon.sh example.com
```

Reports will be saved inside the `output/` folder.

---

## 📝 License

[MIT](LICENSE)

---

## 👤 Author

Made by [Pranav P](https://github.com/YOUR_USERNAME)
