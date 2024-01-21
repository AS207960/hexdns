import json

from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseBadRequest
import django_keycloak_auth
import requests
import jose.jwt
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, get_object_or_404, render, reverse
from django.conf import settings
from django.utils import timezone
import dateutil.parser
import datetime
import hmac
from .. import models, forms


def make_app_token() -> str:
    now = timezone.now()
    return jose.jwt.encode({
        "iat": now,
        "exp": now + datetime.timedelta(minutes=10),
        "iss": settings.GITHUB_APP_ID,
    }, key=settings.GITHUB_PRIVATE_KEY, algorithm=jose.jwt.ALGORITHMS.RS256)


def get_installation_token(installation: models.GitHubInstallation) -> str:
    now = timezone.now()
    if installation.access_token:
        if (installation.access_token_expires_at and installation.access_token_expires_at > now) or (not installation.access_token_expires_at):
            return installation.access_token

    r = requests.post(
        f"https://api.github.com/app/installations/{installation.installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {make_app_token()}",
        }
    )
    r.raise_for_status()
    r_data = r.json()
    access_token = r_data.get("token")
    expiry = dateutil.parser.isoparse(r_data.get("expires_at")) if r_data.get("expires_at") else None
    installation.access_token = access_token
    installation.access_token_expires_at = expiry
    installation.save()

    return access_token


def _github_get_all(url, key, /, params={}, **kwargs):
    params["per_page"] = 100
    params["page"] = 1

    items_out = []

    while True:
        r = requests.get(url, params=params, **kwargs)
        r.raise_for_status()
        r_data = r.json()
        items = r_data[key]
        items_out.extend(items)
        if len(items) == 100:
            params["page"] += 1
        else:
            break

    return items_out


@csrf_exempt
def webhook(request):
    body_sig = request.headers.get("X-Hub-Signature-256")
    if not body_sig:
        return HttpResponseBadRequest()

    if not body_sig.startswith("sha256="):
        return HttpResponseBadRequest()

    body_sig = body_sig[len("sha256="):]

    own_sig = hmac.new(settings.GITHUB_WEBHOOK_SECRET.encode(), request.body, 'sha256').hexdigest()

    if not hmac.compare_digest(body_sig, own_sig):
        return HttpResponseBadRequest()

    webhook_data = json.loads(request.body)

    if "installation" in webhook_data and "action" in webhook_data:
        if webhook_data["action"] == "deleted":
            models.GitHubInstallation.objects.filter(installation_id=webhook_data["installation"]["id"]).delete()

    return HttpResponse(status=200)


@login_required
def oauth_login(request):
    state = models.GitHubState(user=request.user.account)

    if "redirect" in request.GET:
        state.redirect_uri = settings.EXTERNAL_URL_BASE + request.GET["redirect"]

    state.save()
    request.session["github_state_id"] = state.id

    return redirect(f"https://github.com/apps/{settings.GITHUB_APP_NAME}/installations/new?state={str(state.state)}")


@login_required
def oauth_callback(request):
    if "code" not in request.GET or "installation_id" not in request.GET or "setup_action" not in request.GET:
        return HttpResponseBadRequest()

    try:
        installation_id = int(request.GET["installation_id"])
    except ValueError:
        return HttpResponseBadRequest()

    if request.GET["setup_action"] == "update":
        if "state" in request.GET:
            if "github_state_id" not in request.session:
                return redirect('github_oauth_login')

            state = models.GitHubState.objects.filter(id=request.session["github_state_id"]).first()
            if not state:
                return redirect('github_oauth_login')
        else:
            state = None

        installation = models.GitHubInstallation.objects.filter(
            installation_id=installation_id, user=request.user.account).first()
        if not installation:
            return HttpResponseBadRequest()
    else:
        if "github_state_id" not in request.session:
            return redirect('github_oauth_login')

        state = models.GitHubState.objects.filter(id=request.session["github_state_id"]).first()
        if not state:
            return redirect('github_oauth_login')

        installation = None

    if state:
        if request.GET["state"] != str(state.state):
            return HttpResponseBadRequest()

    r = requests.post("https://github.com/login/oauth/access_token", data={
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": request.GET["code"],
        "redirect_uri": settings.EXTERNAL_URL_BASE + request.path,
        "state": str(state.state)
    }, headers={
        "Accept": "application/json"
    })
    if r.status_code != 200:
        return HttpResponseBadRequest()

    if state:
        state.delete()

    r_data = r.json()
    now = timezone.now()
    access_token = r_data.get("access_token")
    access_token_expires_in = datetime.timedelta(seconds=int(r_data.get("expires_in"))) if r_data.get("expires_in") else None
    access_token_expires_at = now + access_token_expires_in if access_token_expires_in else None
    refresh_token = r_data.get("refresh_token")
    refresh_token_expires_in = datetime.timedelta(seconds=int(r_data.get("refresh_token_expires_in"))) if r_data.get("refresh_token_expires_in") else None
    refresh_token_expires_at = now + refresh_token_expires_in if refresh_token_expires_in else None

    if not installation:
        installations = _github_get_all("https://api.github.com/user/installations", "installations", headers={
            "Authorization": f"token {access_token}"
        })
        installation = next(filter(lambda i: i.get("id") == installation_id, installations), None)
        if not installation:
            return HttpResponseBadRequest()

        installation = models.GitHubInstallation(
            user=request.user.account,
            installation_id=installation_id
        )

    installation.user_access_token = access_token
    installation.user_access_token_expires_at = access_token_expires_at
    installation.user_refresh_token = refresh_token
    installation.user_refresh_token_expires_at = refresh_token_expires_at
    installation.save()

    if state and state.redirect_uri:
        return redirect(state.redirect_uri)
    else:
        return redirect("zones")


@login_required
def setup_github_pages(request, zone_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    if request.method == "POST":
        record_form = forms.GithubPagesForm(request.POST)
        if record_form.is_valid():
            models.GitHubPagesRecord(
                zone=zone_obj,
                record_name=record_form.cleaned_data['record_name'],
            ).save()
            zone_obj.last_modified = timezone.now()
            zone_obj.save()

            return redirect('edit_zone', zone_obj.id)
    else:
        record_form = forms.GithubPagesForm()

    installation = models.GitHubInstallation.objects.filter(user=request.user.account).first()
    if installation:
        app_installed = True
        repositories = _github_get_all("https://api.github.com/installation/repositories", "repositories", headers={
            "Authorization": f"token {get_installation_token(installation)}"
        })
    else:
        app_installed = False
        repositories = []

    return render(request, "dns_grpc/github/add_github_record.html", {
        "record_form": record_form,
        "app_installed": app_installed,
        "repositories": repositories,
        "zone": zone_obj,
    })


@login_required
def setup_github_pages_repo(request, zone_id, owner, repo):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    zone_obj = get_object_or_404(models.DNSZone, id=zone_id)
    installation = models.GitHubInstallation.objects.filter(user=request.user.account).first()

    if not installation:
        return redirect(reverse("github_oauth_login") + f"?redirect={request.path}")

    if not zone_obj.has_scope(access_token, 'edit'):
        raise PermissionDenied()

    branches_r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/branches", headers={
        "Authorization": f"token {get_installation_token(installation)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    })

    if branches_r.status_code == 404:
        return render(request, "dns_grpc/error.html", {
            "error": "You don't have permission to manage this repository",
            "back_url": reverse("edit_zone", args=(zone_obj.id,))
        })

    branches_r.raise_for_status()
    branches = branches_r.json()

    pages_r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/pages", headers={
        "Authorization": f"token {get_installation_token(installation)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    })

    if pages_r.status_code == 404:
        if request.method == "POST":
            setup_form = forms.GithubPagesSetupForm(request.POST)
            setup_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))

            if setup_form.is_valid():
                if setup_form.cleaned_data["record_name"] == "@":
                    dns_name = zone_obj.zone_root
                else:
                    dns_name = f"{setup_form.cleaned_data['record_name']}.{zone_obj.zone_root}"

                requests.post(f"https://api.github.com/repos/{owner}/{repo}/pages", headers={
                    "Authorization": f"token {get_installation_token(installation)}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }, json={
                    "source": {
                        "branch": setup_form.cleaned_data["source_branch"],
                        "path": setup_form.cleaned_data["source_path"],
                    }
                }).raise_for_status()
                requests.put(f"https://api.github.com/repos/{owner}/{repo}/pages", headers={
                    "Authorization": f"token {get_installation_token(installation)}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28"
                }, json={
                    "cname": dns_name,
                }).raise_for_status()
                models.GitHubPagesRecord(
                    zone=zone_obj,
                    record_name=setup_form.cleaned_data['record_name'],
                    repo_owner=owner,
                    repo_name=repo,
                    installation=installation,
                ).save()
                zone_obj.last_modified = timezone.now()
                zone_obj.save()

                return redirect('edit_zone', zone_obj.id)
        else:
            setup_form = forms.GithubPagesSetupForm()
            setup_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))

        return render(request, "dns_grpc/github/edit_github_record.html", {
            "title": "Setup GitHub pages deployment",
            "form": setup_form,
            "repo_name": f"{owner}/{repo}"
        })

    else:
        pages_data = pages_r.json()

        if request.method == "POST":
            record_form = forms.GithubPagesSetupForm(request.POST)
            record_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))
            if record_form.is_valid():
                if record_form.cleaned_data["record_name"] == "@":
                    dns_name = zone_obj.zone_root
                else:
                    dns_name = f"{record_form.cleaned_data['record_name']}.{zone_obj.zone_root}"

                requests.put(
                    f"https://api.github.com/repos/{owner}/{repo}/pages",
                    headers={
                        "Authorization": f"token {get_installation_token(installation)}",
                        "Accept": "application/vnd.github+json"
                    }, json={
                        "cname": dns_name,
                        "source": {
                            "branch": record_form.cleaned_data["source_branch"],
                            "path": record_form.cleaned_data["source_path"],
                        }
                    }
                ).raise_for_status()
                models.GitHubPagesRecord(
                    zone=zone_obj,
                    record_name=record_form.cleaned_data['record_name'],
                    repo_owner=owner,
                    repo_name=repo,
                    installation=installation,
                ).save()
                zone_obj.last_modified = timezone.now()
                zone_obj.save()

                return redirect("edit_zone", zone_obj.id)
        else:
            record_form = forms.GithubPagesSetupForm(initial={
                "source_path": pages_data["source"]["path"],
                "source_branch": pages_data["source"]["branch"],
            })
            record_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))

        return render(
            request,
            "dns_grpc/fzone/edit_record.html",
            {"title": "Create GitHub pages record", "form": record_form},
        )


@login_required
def edit_github_pages_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.GitHubPagesRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if user_record.installation:
        installation = user_record.installation
    else:
        installation = models.GitHubInstallation.objects.filter(user=request.user.account).first()

    if not installation and user_record.repo_name:
        return redirect(reverse("github_oauth_login") + f"?redirect={request.path}")

    if user_record.repo_name:
        branches_r = requests.get(
            f"https://api.github.com/repos/{user_record.repo_owner}/{user_record.repo_name}/branches",
            headers={
                "Authorization": f"token {get_installation_token(installation)}"
            }
        )

        branches_r.raise_for_status()
        branches = branches_r.json()

        pages_r = requests.get(
            f"https://api.github.com/repos/{user_record.repo_owner}/{user_record.repo_name}/pages",
            headers={
                "Authorization": f"token {get_installation_token(installation)}"
            }
        )

        if branches_r.status_code == 404 or pages_r.status_code == 404:
            return render(request, "dns_grpc/error.html", {
                "error": "You don't have permission to manage this repository",
                "back_url": reverse("edit_zone", args=(user_record.zone.id,))
            })

        pages_data = pages_r.json()

        if request.method == "POST":
            record_form = forms.GithubPagesSetupForm(request.POST)
            record_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))
            if record_form.is_valid():
                requests.put(
                    f"https://api.github.com/repos/{user_record.repo_owner}/{user_record.repo_name}/pages",
                    headers={
                        "Authorization": f"token {get_installation_token(installation)}",
                        "Accept": "application/vnd.github+json"
                    }, json={
                        "cname": f"{record_form.cleaned_data['record_name']}.{user_record.zone.zone_root}",
                        "source": {
                            "branch": record_form.cleaned_data["source_branch"],
                            "path": record_form.cleaned_data["source_path"],
                        }
                    }
                ).raise_for_status()

                user_record.record_name = record_form.cleaned_data["record_name"]
                user_record.save()
                user_record.zone.last_modified = timezone.now()
                user_record.zone.save()

                return redirect("edit_zone", user_record.zone.id)
        else:
            record_form = forms.GithubPagesSetupForm(initial={
                "record_name": user_record.record_name,
                "source_path": pages_data["source"]["path"],
                "source_branch": pages_data["source"]["branch"],
            })
            record_form.fields['source_branch'].choices = list(map(lambda b: (b["name"], b["name"]), branches))

        return render(
            request,
            "dns_grpc/fzone/edit_record.html",
            {"title": "Edit GitHub pages record", "form": record_form },
        )
    else:
        if request.method == "POST":
            record_form = forms.GithubPagesForm(request.POST)
            if record_form.is_valid():
                user_record.record_name = record_form.cleaned_data["record_name"]
                user_record.save()
                user_record.zone.last_modified = timezone.now()
                user_record.zone.save()

                return redirect("edit_zone", user_record.zone.id)
        else:
            record_form = forms.GithubPagesForm(initial={
                "record_name": user_record.record_name,
            })

        return render(
            request,
            "dns_grpc/fzone/edit_record.html",
            {"title": "Edit GitHub pages record", "form": record_form },
        )


@login_required
def delete_github_pages_record(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.GitHubPagesRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if user_record.installation:
        installation = user_record.installation
    else:
        installation = models.GitHubInstallation.objects.filter(user=request.user.account).first()

    if not installation and user_record.repo_name:
        return redirect(reverse("github_oauth_login") + f"?redirect={request.path}")

    if request.method == "POST":
        if request.POST.get("delete") == "true":
            if user_record.repo_name:
                r = requests.delete(
                    f"https://api.github.com/repos/{user_record.repo_owner}/{user_record.repo_name}/pages",
                    headers={
                        "Authorization": f"token {get_installation_token(installation)}",
                        "Accept": "application/vnd.github+json",
                    }
                )

                if r.status_code not in (204, 404, 403):
                    return render(request, "dns_grpc/error.html", {
                        "error": "Failed to disable GitHub Pages on repository",
                        "back_url": reverse("edit_zone", args=(user_record.zone.id,))
                    })

            user_record.zone.last_modified = timezone.now()
            user_record.zone.save()
            user_record.delete()
            return redirect("edit_zone", user_record.zone.id)

    return render(
        request,
        "dns_grpc/fzone/delete_record.html",
        {"title": "Delete GitHub pages record", "record": user_record, },
    )


@login_required
def github_pages_record_rebuild(request, record_id):
    access_token = django_keycloak_auth.clients.get_active_access_token(oidc_profile=request.user.oidc_profile)
    user_record = get_object_or_404(models.GitHubPagesRecord, id=record_id)

    if not user_record.zone.has_scope(access_token, 'edit'):
        raise PermissionDenied

    if user_record.installation:
        installation = user_record.installation
    else:
        installation = models.GitHubInstallation.objects.filter(user=request.user.account).first()

    if not installation and user_record.repo_name:
        return redirect(reverse("github_oauth_login") + f"?redirect={request.path}")

    r = requests.post(
        f"https://api.github.com/repos/{user_record.repo_owner}/{user_record.repo_name}/pages/builds",
        headers={
            "Authorization": f"token {get_installation_token(installation)}",
            "Accept": "application/vnd.github+json"
        }
    )

    if r.status_code != 201:
        return render(request, "dns_grpc/error.html", {
            "error": "Failed to request rebuild of repository",
            "back_url": reverse("edit_zone", args=(user_record.zone.id,))
        })

    return redirect("edit_zone", user_record.zone.id)
