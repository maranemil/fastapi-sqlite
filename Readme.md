
Start backend

~~~shell
/usr/bin/docker-compose -f docker-compose.yml -p pythonproject1 up -d backend
~~~

Restart backend

~~~shell
/usr/bin/docker-compose -f docker-compose.yml -p pythonproject1 restart backend
~~~

Start api

~~~shell
/usr/bin/docker-compose -f docker-compose.yml -p pythonproject1 up -d api
~~~


Start mailer

~~~shell
/usr/bin/docker-compose -f docker-compose.yml -p pythonproject1 up -d mailer
~~~

~~~
# fast api
http://0.0.0.0:5000/
http://0.0.0.0:5000/docs
~~~

~~~sh
#docker backend: cd src
uvicorn main:app --reload --host 0.0.0.0 --port 5000
~~~