# perfopt-homework

https://perfopt-homework.vercel.app/

This benchmark aims to compare 3 well-know cryptographic libraries:
Bouncy Castle (Java), Node's Cpypto modules and OpenSSL (using C++).
The cryptographic algorithms I have chosen to test using the given
libraries were the following 3 famous algorithms: RSA, SHA-256 and
ChaCha20-Poly1305.

### Report setup using Jupyter notebook and Quarto:

Install quarto: https://quarto.org/docs/get-started/

Start venv (macos and linux command):
```bash
source .venv/bin/activate
```

Running the Jupyter notebook:

```bash
python3 -m jupyter lab report.ipynb
```

Quarto preview command:

```bash
quarto preview report.ipynb
```

Make final `index.html` file using quarto from the notebook:

```
quarto render report.ipynb --to html --output index.html -M embed-resources:true
```
