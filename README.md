# JWATTACKER

jwattacker aims to indentify vulnerabilities and misconfiguration with JWT protected endpoints.

Supported modes:
- JWT authentication bypass via unverified signature
- JWT authentication bypass via flawed signature verification

```                                                                                                       
     @@@  @@@  @@@  @@@   @@@@@@   @@@@@@@  @@@@@@@   @@@@@@    @@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@   
     @@@  @@@  @@@  @@@  @@@@@@@@  @@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  
     @@!  @@!  @@!  @@!  @@!  @@@    @@!      @@!    @@!  @@@  !@@       @@!  !@@  @@!       @@!  @@@  
     !@!  !@!  !@!  !@!  !@!  @!@    !@!      !@!    !@!  @!@  !@!       !@!  @!!  !@!       !@!  @!@  
     !!@  @!!  !!@  @!@  @!@!@!@!    @!!      @!!    @!@!@!@!  !@!       @!@@!@!   @!!!:!    @!@!!@!   
     !!!  !@!  !!!  !@!  !!!@!!!!    !!!      !!!    !!!@!!!!  !!!       !!@!!!    !!!!!:    !!@!@!    
     !!:  !!:  !!:  !!:  !!:  !!!    !!:      !!:    !!:  !!!  :!!       !!: :!!   !!:       !!: :!!   
!!:  :!:  :!:  :!:  :!:  :!:  !:!    :!:      :!:    :!:  !:!  :!:       :!:  !:!  :!:       :!:  !:!  
::: : ::   :::: :: :::   ::   :::     ::       ::    ::   :::   ::: :::   ::  :::   :: ::::  ::   :::  
 : :::      :: :  : :     :   : :     :        :      :   : :   :: :: :   :   :::  : :: ::    :   : :  

usage: jwattacker.py [mode] [options]

modes:
-----------------------------------------------------
0: Runs all checks
1: Authentication bypass via unverified signature
2: Authentication bypass via unsigned token
-----------------------------------------------------

options:
  -h, --help                    show this help message and exit
  --mode MODE                   Choose one of the modes above
  -u URL                        Full url to protected endpoint, e.g. https://google.com
  -m HTTP_METHOD                Endpoint http method, e.g. POST, GET, PUT, DELETE
  -j PATH_TO_JWT                Local path to file containing JWT
  -hk JWT_HEADER_KEY            JWT header key
  -pfx JWT_HEADER_PREFIX        Prefix in header value, e.g. Bearer
  -S SUCCESS_MESSAGE            A string to look in response content when request gives authenticated result, default it will look for 200 response code

```

