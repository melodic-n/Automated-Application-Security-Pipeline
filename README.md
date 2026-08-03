# Automated-Application-Security-Pipeline

During development, having only a dev team that manages everything from conception to deployment (or no security team/individual), they can easily miss security vulnerabilities such as exposed credentials  or an outdated dependency, and it can go undetected until an adversary finds out about it and exploit it. 

There are open source tools available for static vulnerability analysis like Semgrep, Gitleak , npm audit and more but you would have to run them individually and manually,so i thought about it and decided to create an automated system to check immediately a repository (or branch) for vulnerabilities and report them by producing a report or link it to a dashboard and trigger an alert (if we were using ELK stash).


## Architecture
 
```mermaid
flowchart TD
    A[("📦 Developer Repository")] --> B["🔍 Repository Scanner"]
 
    B --> C1["🧪 Semgrep<br/><sub>Static Analysis</sub>"]
    B --> C2["🔑 Gitleaks<br/><sub>Secret Detection</sub>"]
    B --> C3["📚 Dependency Check<br/><sub>SCA / CVEs</sub>"]
 
    C1 --> D["🧬 Finding Normalizer"]
    C2 --> D
    C3 --> D
 
    D --> E["🔗 Correlation Engine"]
    E --> F["⚖️ Risk Prioritization"]
 
    F --> G1["📊 Dashboard"]
    F --> G2["📄 PDF Report"]
    F --> G3["🌐 REST API"]
 
    classDef source fill:#1f2937,stroke:#60a5fa,stroke-width:2px,color:#fff
 classDef scanner fill:#0f766e,stroke:#5eead4,stroke-width:2px,color:#fff
    classDef process fill:#7c3aed,stroke:#c4b5fd,stroke-width:2px,color:#fff
    classDef output fill:#b45309,stroke:#fcd34d,stroke-width:2px,color:#fff
 
    class A source
    class B,C1,C2,C3 scanner
    class D,E,F process
    class G1,G2,G3 output
```
## Tech Stack
 
- **SAST:** [Semgrep](https://semgrep.dev/)
- **Secret Scanning:** [Gitleaks](https://github.com/gitleaks/gitleaks)
- **SCA:** [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

# Getting Started

## 1. Clone the repository

```bash
git clone <repository-url>
cd <repository-name>
```

## 2. Install the required tools

Run the installation script:

```bash
./installtools.sh
```

## 3. Run the scanner

### Scan a GitHub repository

```bash
python main.py https://github.com/<org>/<repository>
```

### Scan a specific branch

```bash
python main.py https://github.com/<org>/<repository> --branch main
```

### Scan a local repository

```bash
python main.py /path/to/local/repository --local
```

## Examples

```bash
# Scan the default branch
python main.py https://github.com/openai/openai-python

# Scan a specific branch
python main.py https://github.com/openai/openai-python --branch dev

# Scan a local repository
python main.py ~/Projects/my-app --local
```
   
