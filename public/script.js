const socket = io('/');
const videogrid = document.getElementById('video-grid');
const peers = {};
const newPeer = new Peer(undefined, {
    host: '',
    port: ''
});
const myVideo = document.createElement('video');
myVideo.muted = true;

if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true
    }).then(stream => {
        addVideo(myVideo, stream);
        
        // Handle incoming calls
        newPeer.on('call', call => {
            call.answer(stream);
            const video = document.createElement('video');
            call.on('stream', userVideoStream => {
                addVideo(video, userVideoStream);
            });
        });

        // Handle user connection
        socket.on('user-connected', userId => {
            startCallWithNewUser(userId, stream);
        });

        // Handle user disconnection
        socket.on('user-disconnected', userId => {
            if (peers[userId]) peers[userId].close();
        });
    }).catch(error => {
        console.error('Error accessing media devices.', error);
        alert("Unable to access the camera. Please check your device settings.");
    });
} else {
    console.error("Media devices not supported.");
    alert("Your device does not support camera access.");
}

newPeer.on('open', id => {
    socket.emit('join-room', ROOM_ID, id);
});

function addVideo(video, stream) {
    video.srcObject = stream;
    video.addEventListener('loadedmetadata', () => {
        video.play().catch(error => {
            console.error("Error playing video:", error);
        });
    });
    videogrid.append(video);
}

function startCallWithNewUser(userId, stream) {
    const call = newPeer.call(userId, stream);
    const video = document.createElement('video');

    call.on('stream', userVideoStream => {
        addVideo(video, userVideoStream);
    });

    call.on('close', () => {
        video.remove();
    });

    peers[userId] = call;
}
