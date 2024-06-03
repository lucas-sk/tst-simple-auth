import { PrismaClient } from "@prisma/client";
import fastify from "fastify";
import bcrypt from "bcryptjs";
import fastifyJwt from "@fastify/jwt";
import fastifyCookie from "@fastify/cookie";
import { verifyJwt } from "./verify-jwt";


const app = fastify()
app.register(fastifyCookie)
app.register(fastifyJwt, { secret: 'supersecret' })
const prisma = new PrismaClient()

app.get("/", async (request, reply) => {
  return { hello: "world" }
})

app.post('/users', async (request, reply) => {
  const { email, password } = request.body

  const alreadyExistSameEmail = await prisma.user.findFirst({
    where: {
      email
    }
  })

  if (alreadyExistSameEmail) {
    reply.status(400)
    return {
      error: "Email already in use"
    }
  }

  const hashedPassword = await bcrypt.hash(password, 8)

  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword
    }
  })

  reply.status(201)
})

app.post('/auth/login', async (request, reply) => {
  const { email, password } = request.body

  const user = await prisma.user.findFirst({
    where: {
      email
    }
  })

  if (!user) {
    reply.status(401)
    return {
      error: "Invalid credentials"
    }
  }

  const passwordMatch = await bcrypt.compare(password, user.password)

  if (!passwordMatch) {
    reply.status(401)
    return {
      error: "Invalid credentials"
    }
  }

  const token = await reply.jwtSign({
    sign: {
      sub: user.id
    }
  })

  return reply.send({
    token
  })
})

app.get('perfil', {
  onRequest: verifyJwt
} , async (request, reply) => {
  const user = await prisma.user.findFirst({
    where: {
      id: request.user.sub
    },
  })

  return {
    user
  }
})


app.listen({
  port: 3000,
}).then(() => {
  console.log("Server running on port 3000")
})