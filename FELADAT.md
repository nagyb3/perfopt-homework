# Teljesítmény-optimalizált szoftverek – Nagy házi feladat téma

Név: Nagy Bence, HVTDD4

## Házi feladat téma:

- Kriptográfiai könyvtárak futási idejének összehasonlítása, illetve egy kriptográfiai algoritmus saját implementációja és összehasonlítása az open-source könyvtárakkal.
- Tesztelendő open-source könyvtárak / modulok
  - **Bouncy Castle (Java):** [https://www.bouncycastle.org/](https://www.bouncycastle.org/)

  - **OpenSSL (C++):** [https://openssl-library.org/](https://openssl-library.org/) (EVP függvényekkel: [OpenSSL Wiki](https://wiki.openssl.org/index.php/EVP))
  - **Node.JS Crypto module (TypeScript):** [https://nodejs.org/api/crypto.html](https://nodejs.org/api/crypto.html)

- Az összeshasonlítás témája a következő kriptográfiai algoritmusok:
  1.  **ChaCha20**
  2.  **RSA**
  3.  **SHA-256**
- Az RSA és ChaCha20 cypherek esetében az encoding és a decoding is a mérés tárgya lesz.
- A projektben összesen 10 mérés fog elkészülni: 9 darab open-source könyvtárakon, 1 darab saját implementáción.
- Az összehasonlítások során az egyetlen metrika amely mérésre és kiértékelésre kerül az a futási idő.
- A mérések egyszálú végrehajtások mellett fognak megvalósulni.
