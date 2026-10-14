import { FastifyReply, FastifyRequest } from 'fastify'
import { checkPassword, verifyPassword, setPassword } from '../controllers/password'

export default [
  {
    method: 'GET',
    url: '/api/password/check',
    handler: async (request: FastifyRequest, reply: FastifyReply) => {
      return checkPassword(request, reply)
    },
  },
  {
    method: 'POST',
    url: '/api/password/verify',
    handler: verifyPassword,
  },
  {
    method: 'POST',
    url: '/api/password/set',
    handler: setPassword,
  },
]
