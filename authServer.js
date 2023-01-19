require("dotenv").config()

const express = require("express")
const app = express()
const jwt = require("jsonwebtoken")

app.use(express.json())

let refreshTokens = []

app.post("/login", (req, res) => {
  // Authentication
  const username = req.body.username
  const user = { name: username }

  const accessToken = generateAccessToken(user)
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

  refreshTokens.push(refreshToken)

  res.json({
    access_token: accessToken,
    refresh_token: refreshToken,
  })
})

app.post("/refreshToken", (req, res) => {
  const refreshToken = req.body.refresh_token
	console.log(refreshToken, 'refresth token');

  if (refreshToken == null) return res.status(401).send("Unauthorized")

  // Check to see if the Refresh Token we pass in the body of the request
  // is in the refreshTokens list
  if (!refreshTokens.includes(refreshToken))
    return res.status(403).send({ message: "Forbidden" })

  // Remove old refresh token from refreshTokens list using Refresh Token Rotation
  // https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
  refreshTokens = refreshTokens.filter(c => c != refreshToken)

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).send({ message: "Forbidden" })

    const accessToken = generateAccessToken({ name: user.name })
    const refreshToken = generateRefreshToken({ name: user.name })

    res.json({ access_token: accessToken, refresh_token: refreshToken })

    refreshTokens.push({ refresh_token: refreshToken })
  })
})

app.delete("/logout", (req, res) => {
  // Invalidate the Refresh Token we pass to the request body
  refreshTokens = refreshTokens.filter(
    access_token => access_token !== req.body.access_token
  )
  res.sendStatus(204)
})

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRATION || "10m",
  })
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRATION || "20m",
  })
}

app.listen(2000)
