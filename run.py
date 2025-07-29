from app import create_app
import config
import webbrowser
import time

app = create_app()

if __name__ == '__main__':
    # Delay for Flask to start before opening browser
    time.sleep(1)
    url = f"http://{config.HOST}:{config.PORT}"
    webbrowser.open(url)

    app.run(host=config.HOST, port=config.PORT, debug=True)
