from flask import Flask, render_template_string

from utils.rabbit_controller import RabbitMqController

app = Flask(__name__)
alerts = []

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
<title>Alert Server</title>
</head>
<body><span id="alert"><span></body>
</html>""")

#<body>Latest Alert: <span id="alert"><span></body>
@app.route('/getevents')
def getevents():
    """send current content"""
    controller = RabbitMqController()
    alert = controller.get_alert()
    if alert is not None:
        alert_str = f'<br><p style="color:red;">Alert type:</p> {alert.name} ' \
                    f'<p style="color:blue;">Information:</p> {alert.information} <br>'
        if len(alerts) is 6:
            alerts.clear()
        alerts.append(alert_str)
        alerts_str = '\n'.join(map(str, alerts))
    else:
        alerts_str = '\n'.join(map(str, alerts))
    return alerts_str

if __name__ == "__main__":
    app.run(debug=True)