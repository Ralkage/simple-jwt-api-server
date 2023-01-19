require("dotenv").config()

const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")

app.use(express.json())

const posts = []

app.post("/posts", authenticateToken, (req, res) => {
  const username = req.body.username
  const title = req.body.title

  posts.push({ username: username, title: title })

  res.json({ username: username, title: title })
})

app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.username === req.user.name))
})

app.get("/validateToken", authenticateToken, (req, res) => {
  res.status(200).send({ message: "The Access Token you provided is valid!" })
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (token == null) return res.status(401).send({ message: "Unauthorized" })

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(401).send({ message: "Unauthorized" })
    req.user = user
    next()
  })
}

app.listen(3000)

