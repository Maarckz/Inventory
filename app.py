
from asgiref.wsgi import WsgiToAsgi

from core.app import create_app, run_server

app = create_app()
asgi_app = WsgiToAsgi(app)

if __name__ == '__main__':
    run_server(app)
