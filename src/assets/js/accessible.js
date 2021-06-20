function setCookie(name, val, exp) {
    var d = new Date();
    d.setTime(d.getTime() + (exp*24*60*60*1000)); // expiry in days
    var expires = "expires=" + d.toUTCString();
    document.cookie = name + "=" + val + ";" + expires + ";path=/";
}

function getCookie(name) {
    name += "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

if (getCookie("accessible") == "") {
    setCookie("accessible", "0", 365);
}

if ((getCookie("accessible") & 1) > 0) {  // High contrast mode
    document.body.classList.add("contrast");
    $("#high-contrast input").attr("checked", "");
}

if ((getCookie("accessible") & 2) > 0) {  // Magnifier
    document.body.classList.add("zoom");
    $("#magnifier input").attr("checked", "");
}

function toggleContrast() {
    document.body.classList.toggle("contrast");
    setCookie("accessible", getCookie("accessible") ^ 1, 1000);
    if (document.body.classList.contains("contrast")) {
        $("#high-contrast input").attr("checked", "");
    } else {
        $("#high-contrast input").removeAttr("checked");
    }
}

function toggleZoom() {
    document.body.classList.toggle("zoom");
    setCookie("accessible", getCookie("accessible") ^ 2, 1000);
    if (document.body.classList.contains("zoom")) {
        $("#magnifier input").attr("checked", "");
    } else {
        $("#magnifier input").removeAttr("checked");
    }
}

$("#high-contrast").on("click", toggleContrast);
$("#magnifier").on("click", toggleZoom);