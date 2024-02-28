## DDTank Lua Wrapper ![LICENSE_BADGE]

This is a Lua wrapper for the game DDTank, the WAN version of it on mobile.
Using this you can execute lua code within the game, make custom scripts, modify the game, assets and whatever you'd like.
This is for educational purposes mainly, I am not working on this anymore but I am open to pull requests.

## Built With

This is using Frida under the hood, allowing to interact with the phone memory. It does not require rooting your device, you need to be plugged in to your mobile though.

## Getting Started

Before running this you will need to install some requirements.

1. Setup frida server on your phone
2. Install NodeJS
3. Install Python and the libaries required ``pip install -r requirements.txt``
4. Run ``python server.py``
5. Visit the website it gives.

Endpoints : 
1. "/loadScript", runs the game and sets up the code execution
2. "/dumpCode", runs the game and dumps the lua code.

Once the server is started run the first endpoint and then you will be able to execute your lua scripts.

## License
Distributed under the MIT License. See `LICENSE` for more information.

![LUA] ![PYTHON] ![JAVASCRIPT] ![MADE_WITH]

[LUA]: https://img.shields.io/badge/Lua-2C2D72?style=for-the-badge&logo=lua&logoColor=white
[JAVASCRIPT]: https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black
[PYTHON]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[MADE_WITH]: http://ForTheBadge.com/images/badges/built-with-love.svg
[LICENSE_BADGE]: https://img.shields.io/github/license/0xdefnoterr/DDTankLuaWrapper?style=for-the-badge&labelColor=%23100f1a&color=%236d5dfc
