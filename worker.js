
const worker = new Worker("worker.js");

worker.onmessage = (event) => {
    console.log(event.data); // Akan menampilkan: WOLLEZ
    document.body.innerText = event.data; // Menampilkan di halaman
};
