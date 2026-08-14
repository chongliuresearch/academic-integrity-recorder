# Opt-in zsh integration for Academic Integrity Recorder.
# Source this file only in a selected research terminal. Events are accepted
# only after all four AIR_RECORDER_* pairing values below are configured.
typeset -g AIR_RECORDER_ENDPOINT="${AIR_RECORDER_ENDPOINT:-http://127.0.0.1:43119/v1/events}"
typeset -g AIR_LAST_RESEARCH_COMMAND=""
typeset -g AIR_LAST_COMMAND_IS_SENSITIVE="0"

air_recorder_preexec() {
  [[ "${AIR_RECORDER_ENABLED:-0}" != "1" ]] && return
  local lowered="${(L)1}"
  # Commands commonly carrying inline credentials are metadata-only. This is
  # intentionally conservative; false positives cost detail, not secrecy.
  if [[ "$lowered" =~ '(password|passwd|passphrase|secret|api[_-]?key|access[_-]?token|authorization|bearer|sshpass|--user|-u[[:space:]]|mysql[[:space:]].*-p|login|credential)' ]]; then
    AIR_LAST_RESEARCH_COMMAND=""
    AIR_LAST_COMMAND_IS_SENSITIVE="1"
  else
    AIR_LAST_RESEARCH_COMMAND="$1"
    AIR_LAST_COMMAND_IS_SENSITIVE="0"
  fi
}

air_recorder_precmd() {
  local exit_code="$?"
  [[ "${AIR_RECORDER_ENABLED:-0}" != "1" ]] && return
  [[ -z "${AIR_RECORDER_TOKEN:-}" || -z "${AIR_RECORDER_PROJECT_ID:-}" || -z "${AIR_RECORDER_SOURCE_ID:-}" ]] && return
  [[ -z "$AIR_LAST_RESEARCH_COMMAND" && "$AIR_LAST_COMMAND_IS_SENSITIVE" != "1" ]] && return

  AIR_COMMAND="$AIR_LAST_RESEARCH_COMMAND" \
  AIR_CWD="$PWD" \
  AIR_EXIT="$exit_code" \
  AIR_SENSITIVE="$AIR_LAST_COMMAND_IS_SENSITIVE" \
  AIR_ENDPOINT="$AIR_RECORDER_ENDPOINT" \
  AIR_TOKEN="$AIR_RECORDER_TOKEN" \
  AIR_PROJECT="$AIR_RECORDER_PROJECT_ID" \
  AIR_SOURCE_ID="$AIR_RECORDER_SOURCE_ID" \
  python3 -c 'import base64,datetime,hashlib,hmac,json,os,urllib.request,uuid
source="shell-opt-in"
kind="commandExecuted"
sensitive=os.environ["AIR_SENSITIVE"]=="1"
payload=({"action":"sensitive-command-executed","commandStored":False,"workingDirectory":os.environ["AIR_CWD"],"workingDirectoryStored":False,"exitCode":int(os.environ["AIR_EXIT"]),"foreground":True} if sensitive else {"command":os.environ["AIR_COMMAND"],"workingDirectory":os.environ["AIR_CWD"],"exitCode":int(os.environ["AIR_EXIT"]),"foreground":True})
canonical=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(",",":"))
payload_hash=hashlib.sha256(canonical.encode()).hexdigest()
occurred_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
message_id=str(uuid.uuid4())
project=os.environ["AIR_PROJECT"]
source_id=os.environ["AIR_SOURCE_ID"]
signing="\n".join((project,source,source_id,message_id,occurred_at,kind,"",payload_hash)).encode()
signature=base64.urlsafe_b64encode(hmac.new(os.environ["AIR_TOKEN"].encode(),signing,hashlib.sha256).digest()).rstrip(b"=").decode()
body=json.dumps({"projectId":project,"source":source,"sourceId":source_id,"messageId":message_id,"occurredAt":occurred_at,"payloadHash":payload_hash,"signature":signature,"kind":kind,"privateMode":False,"passwordField":sensitive,"payload":payload},ensure_ascii=False,separators=(",",":")).encode()
request=urllib.request.Request(os.environ["AIR_ENDPOINT"],data=body,method="POST",headers={"Authorization":"Bearer "+os.environ["AIR_TOKEN"],"Content-Type":"application/json"})
try: urllib.request.urlopen(request,timeout=1).read()
except Exception: pass' >/dev/null 2>&1 &!

  AIR_LAST_RESEARCH_COMMAND=""
  AIR_LAST_COMMAND_IS_SENSITIVE="0"
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec air_recorder_preexec
add-zsh-hook precmd air_recorder_precmd
