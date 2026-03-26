from datetime import datetime

gui_output=None

gui_mode=False

def set_output(widget):

    global gui_output,gui_mode

    gui_output=widget

    gui_mode=True


def alert(message,src="N/A",dst="N/A",level="WARNING"):

    time=datetime.now().strftime("%H:%M:%S")

    text=f"[{level}] {time} | {message} | {src} → {dst}"

    # Terminal only if CLI mode
    if not gui_mode:

        print("\n"+text+"\n")

    # GUI output
    if gui_output:

        gui_output.insert("end","\n"+text+"\n")

        gui_output.see("end")

    # Log file
    with open("alerts.log","a") as f:

        f.write(text+"\n")