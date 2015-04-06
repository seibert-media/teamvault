from django.core.mail import EmailMultiAlternatives
from django.template import Context
from django.template.loader import get_template, TemplateDoesNotExist
from django.utils import translation


def send_mail(users_to, subject, template,
              user_from=None, context={}, lang="en",
              attachments=None):
    if attachments is None:
        attachments = []
    c = Context(context)
    translation.activate(lang)
    text_mail = get_template(template + ".txt").render(c)

    msg = EmailMultiAlternatives(
        subject,
        text_mail,
        user_from.email,
        [user.email for user in users_to],
    )

    try:
        html_mail = get_template(template + ".html").render(c)
        msg.attach_alternative(html_mail, "text/html")
    except TemplateDoesNotExist:
        pass

    for filename, data, content_type in attachments:
        msg.attach(filename, data, content_type)

    msg.send()
