from flask import Flask, render_template_string

from utils.rabbit_controller import RabbitMqController

app = Flask(__name__)

@app.route("/")
def index():
    return render_template_string("""<!DOC html>
<html>
<head>
<script type="text/javascript" src="http://code.jquery.com/jquery-1.8.0.min.js"></script>
<script type="text/javascript">
(function worker() {
  $.get('/getevents', function(getevents) {
    $('#alert').html(getevents);    
    setTimeout(worker, 1000); // run `worker()` again after 1000ms (1s)
  });
})();
</script>
<meta charset="utf-8" />
<title>Test</title>
</head>
<body>Latest Alert: <span id="alert"><span></body>
</html>""")


@app.route('/getevents')
def getevents():
    """send current content"""
    controller = RabbitMqController()
    alert = controller.get_alert()
    return f"Alert type: {alert.name} . Information: {alert.information}"

if __name__ == "__main__":
    app.run(debug=True)