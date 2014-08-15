kareha-psgi
===========

## Intro ##
This is the same Kareha you all know and love with a potentially huge speed boost.

## How To Use ##
1. Grab Kareha from this repo.

        $ git clone https://github.com/marlencrabapple/kareha-psgi.git

2. Follow whatever instructions are provided on http://wakaba.c3.cx/s/web/wakaba_kareha for configuring Kareha, and then run the following. You won't have to do anything else if you're only interested in seeing what this is all about. An actual production install requires a little more work and is dependent on your server setup, needs, and software preferences.

        $ cd <your install dir>
        $ sudo cpanm --installdeps .
        $ plackup app.psgi
