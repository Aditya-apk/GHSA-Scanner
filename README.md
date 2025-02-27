# GitHub Advisory Scanner (GHSA Scanner)

A powerful web-based security tool to scan GitHub Security Advisories (GHSA) for CVEs and analyze related commits. This tool helps security researchers, developers, and organizations track and analyze security vulnerabilities in their dependencies.

## 📸 Demo
In this demonstration, we showcase the tool's intuitive workflow: A security researcher searches for a specific CVE, instantly receiving comprehensive details about the vulnerable package and its security implications. The interface then allows for precise version selection, enabling users to analyze specific releases or tags. The powerful commit search functionality helps users locate specific commits either by their ID or through relevant commit messages, streamlining the security investigation process.

![GHSA Scanner Working Demo](Working_demo.png)

## 🔍 Features
- Search and analyze CVEs in GitHub Security Advisories
- Detailed package vulnerability information and impact analysis
- Version-based commit analysis (releases and tags)
- Real-time commit visualization
- Advanced commit search and filtering
- Direct links to GitHub commits for detailed investigation

## 🚀 Key Benefits
- Quick vulnerability assessment
- Easy tracking of security patches
- Efficient commit history analysis
- Time-saving security research
- Seamless GitHub integration

## 🛠️ Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your GitHub token:
   ```plaintext:.env
   GITHUB_TOKEN=your_github_token
```