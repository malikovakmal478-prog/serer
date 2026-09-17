const http = require("http");

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8"
  });

  res.end(JSON.stringify({
    success: true,
    message: "UzbekServer ishlayapti! 🚀",
    time: new Date().toISOString()
  }));
});

server.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});
