import streamlit as st
import requests
from datetime import datetime

st.set_page_config(page_title="Repo Patch Automator", layout="centered")
st.title("Patch uploader → GitHub Actions trigger 🔁")
st.markdown(
    "Upload a `.patch` file or paste patch content. This will create a private Gist and trigger the repo workflow to apply it."
)

# Read required secrets (set these in Streamlit secrets)
try:
    BOT_TOKEN = st.secrets["BOT_TOKEN"]
    REPO_OWNER = st.secrets["REPO_OWNER"]
    REPO_NAME = st.secrets["REPO_NAME"]
    DEFAULT_REF = st.secrets.get("DEFAULT_REF", "main")
except Exception:
    st.error("Missing Streamlit secrets. Add BOT_TOKEN, REPO_OWNER, REPO_NAME in Streamlit secrets.")
    st.stop()

uploaded_file = st.file_uploader("Upload patch file (.patch) or paste below", type=["patch","diff","txt"])
manual_patch = st.text_area("Or paste patch content here", height=200)

target_branch = st.text_input("Target branch (workflow will run on this branch)", value=DEFAULT_REF)
commit_message = st.text_input("Commit message", value=f"Apply patch via Streamlit at {datetime.utcnow().isoformat()}Z")

if st.button("Create Gist & Trigger Workflow"):
    content = ""
    if uploaded_file is not None:
        try:
            content = uploaded_file.read().decode("utf-8")
        except Exception:
            st.error("Could not read the uploaded file as utf-8. Try copying/pasting the patch instead.")
            st.stop()
    elif manual_patch.strip():
        content = manual_patch
    else:
        st.error("Please upload a patch or paste patch content.")
        st.stop()

    # Create gist
    gist_api = "https://api.github.com/gists"
    gist_payload = {
        "description": f"Automated patch created at {datetime.utcnow().isoformat()}Z",
        "public": False,
        "files": {"patch.diff": {"content": content}}
    }
    headers = {"Authorization": f"token {BOT_TOKEN}", "Accept": "application/vnd.github+json"}
    resp = requests.post(gist_api, headers=headers, json=gist_payload)
    if resp.status_code not in (200, 201):
        st.error(f"Failed to create Gist: {resp.status_code} — {resp.text}")
        st.stop()

    gist = resp.json()
    raw_url = list(gist["files"].values())[0]["raw_url"]
    st.success("Gist created.")
    st.write("Gist URL:", gist.get("html_url"))
    st.write("Raw URL:", raw_url)

    # Trigger workflow
    workflow_filename = "apply-patch.yml"
    dispatch_api = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/workflows/{workflow_filename}/dispatches"
    dispatch_payload = {
        "ref": target_branch,
        "inputs": {
            "patch_url": raw_url,
            "target_branch": target_branch,
            "commit_message": commit_message
        }
    }
    dispatch_resp = requests.post(dispatch_api, headers=headers, json=dispatch_payload)
    if dispatch_resp.status_code in (204, 201):
        st.success("Workflow dispatched. Check Actions tab in your repository.")
        st.write(f"https://github.com/{REPO_OWNER}/{REPO_NAME}/actions")
    else:
        st.error(f"Failed to dispatch workflow: {dispatch_resp.status_code} — {dispatch_resp.text}")
