from Models.alert_model import Alert
from utils.rabbit_controller import RabbitMqController

if __name__ == '__main__':
    controller = RabbitMqController()
    controller.send_alert(Alert("asd", "asdsad"))
    ret = controller.get_alert()
    print(ret)
