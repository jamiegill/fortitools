
import os
from flask_script import Manager
from esp_decrypt import app

manager = Manager(app)
@manager.command
def run():
    port = int(os.environ.get('PORT', 8080))
    app.run(host="0.0.0.0", port=port)

run()
