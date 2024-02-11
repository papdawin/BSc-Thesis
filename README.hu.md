## Weboldal defacement detektáló eszköz fejlesztése
#### Programtervező informatikus BSc Szakdolgozat
###### Veszprém, 2023.05.02

[![en](https://img.shields.io/badge/version-English-blue.svg)](https://github.com/papdawin/thesis/README.md)
[![hu](https://img.shields.io/badge/version-Hungarian-brown.svg)](https://github.com/papdawin/thesis/README.hu.md)

Szakdolgozatom témájának egy weboldal defacement támadást detektáló eszköz
fejlesztését választottam, melynek feladata többek között az injekciós támadásoktól
megvédeni a webszervert. Ez azért is fontos terület napjainkban, mert a felhasználói
adatok védelme az egyik legfontosabb tényező a webes alkalmazások számára és egy
WAF nagyban növelheti alkalmazásunk biztonságát. Mivel az injekciós támadások
jelentik a legnagyobb veszélyt a webes alkalmazásokra, ezért ezek részletes áttekintése
után hozzáláttam a feladat megvalósításához. A fejlesztett szoftver tartalmaz megoldást
a főbb támadást vektorok kivédésére, mint például az SQL injection, az XSS vagy a
Prototype Pollution.
A szoftver megoldásom egy WAF-proxy formájában készült el, ami a kéréseket
továbbítja a kiszolgáló webszerver felé, majd továbbítja a válaszokat a kliens oldalra.
Szakdolgozatomban részletesen bemutatom a WAF megoldások főbb koncepcióit és az
alkalmazott technikákat. A védelem szabad megválasztása érdekében egy konfigurációs
fájlban személyre lehet szabni a programot a kívánt beállításokkal. Továbbá a
felhasználók számára a visszajelzést egy naplófájl és egy IP adatbázis segíti. A
naplófájlban a program rögzíti az esetleges behatolási kísérleteket, illetve az IP
adatbázisban menti a támadó IP címét, szükség esetén online ellenőrzi, hogy a cím nem
szerepel-e feketelistákon.
A védelem tartalmaz egy megoldást, ami mintákat keres a kérésben, illetve egy gépi
tanulást alkalmazó megközelítést. Elvégeztem mindkét megoldás részletes kiértékelését
és tesztelését, továbbá írtam a gépi tanulás további lehetőségeiről a területen. A tervezés,
megvalósítás és tesztelés folyamatát részletesen ismertettem.

