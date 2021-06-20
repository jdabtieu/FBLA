const synth = window.speechSynthesis;

function say(element) {
    synth.speak(new SpeechSynthesisUtterance(element.innerText));
}