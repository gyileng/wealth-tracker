import { DataTypes, Model, Op } from 'sequelize'
import { sequelize } from './index'
import crypto from 'crypto'

export const SESSION_TTL_SECONDS = 30 * 60

class Session extends Model {
  declare id: string
  declare expiresAt: Date
}

Session.init(
  {
    id: {
      type: DataTypes.STRING,
      primaryKey: true,
    },
    expiresAt: {
      type: DataTypes.DATE,
      allowNull: false,
    },
  },
  {
    sequelize,
    modelName: 'Session',
  },
)

export const createSession = async (): Promise<string> => {
  const sessionId = crypto.randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000)

  await Session.create({
    id: sessionId,
    expiresAt,
  })

  return sessionId
}

export const validateSession = async (sessionId: string, renew = false): Promise<boolean> => {
  const session = await Session.findByPk(sessionId)
  if (!session) return false

  const now = Date.now()
  if (now >= session.expiresAt.getTime()) {
    await session.destroy()
    return false
  }

  if (renew) {
    await session.update({ expiresAt: new Date(now + SESSION_TTL_SECONDS * 1000) })
  }

  return true
}

export const clearExpiredSessions = async () => {
  const now = new Date()
  await Session.destroy({
    where: {
      expiresAt: {
        [Op.lt]: now,
      },
    },
  })
}

export default Session
