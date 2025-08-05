from django.urls import path
from .views import (
    RevalidateCardView,
    PollerStartAllView,
    PollerStopAllView,
)

urlpatterns = [
    path("poll/start-all/", PollerStartAllView, name="poll-start-all"),
    path("poll/stop-all/", PollerStopAllView, name="poll-stop-all"),
    path("revalidate", RevalidateCardView, name="revalidate-card"),
]