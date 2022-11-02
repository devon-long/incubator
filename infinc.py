'''
Copyright 2021 Lok Yan

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

import math #for sqrt
import time #for sleep
import threading #Thread

class SimpleThermometer :
    def __init__ (self, source) :
        self.source = source

    def setSource(self, source) :
        self.source = source

    def getTemperature(self) :
        return self.source.getTemperature()

'''
Very simple heater that turns on and pumps the powerOutput (watts).
'''
class SimpleHeatGenerator :
    def __init__ (self, powerOutput, setTemperature, thermometer) :
        self.power = powerOutput
        self.setTemperature = setTemperature 
        self.thermometer = thermometer

    def setThermometer(self, thermo) :
        self.thermometer = thermo

    ''' 
    Returns the number of Watts output by this heater for this timestep.
    '''
    def getOutput(self) :
        if self.thermometer :
            if self.thermometer.getTemperature() < self.setTemperature :
                return self.power
        return 0

BODY_TEMP = (273 + 37)
ROOM_TEMP = (273 + 20)

'''
This class represents a very simple human body (in the general sense).
'''
class Human :

    DENSITY = 1000         # UNIT: kg / m**3
    SPECIFIC_HEAT = 3500   # UNIT: J / kg / degK
    THERMAL_TRANSFER = 5.5 # UNIT: J / s / m**2 / degK

    def __init__ (self, mass, length, temperature) :
        threading.Thread.__init__(self) #init the thread parts

        self.mass = mass                           # UNIT: kg
        self.length = length                       # UNIT: m
        self.bodyHeater = SimpleHeatGenerator(100, BODY_TEMP, self)
                                                   # UNIT: W = J / s
        self.temperature = temperature             # UNIT: degK

        self.surfaceArea = math.sqrt(self.mass * self.length * 100 / 3600)
                                                   # UNIT: m**2
        self.volume = self.mass / Human.DENSITY # UNIT: m**3, by density
        self.energy = self.calculateEnergy()       # UNIT: J

    def setHeater(self, bhg) :
        self.bodyHeater = bhg

    def calculateEnergy(self) :
        # The energy content is calculated based on the current temperature    
        return (Human.SPECIFIC_HEAT * self.mass * self.temperature)

    def calculateTemperature(self) :
        # The temperature is based on the amount of energy
        return (self.energy / Human.SPECIFIC_HEAT / self.mass)

    def getEnergy(self) :
        return self.energy

    def getTemperature(self) :
        return self.temperature

    def getVolume(self) :
        return self.volume

    def addEnergy(self, e) :
        self.energy += e 
        #update the temperature
        self.temperature = self.calculateTemperature()

    def simulateTransferWithChamber(self, timestep, envTemp) :
        # envTemp is the temperature of the environment
        # so we will have to calculate the temperature difference first
        tempDiff = envTemp - self.temperature

        # then figure out how much energy was generated by heater
        if self.bodyHeater :
            energyHeater = self.bodyHeater.getOutput() * timestep # UNIT: J
        else :
            energyHeater = 0

        # then using temperature difference how much energy transferred
        energyTransfer = Human.THERMAL_TRANSFER * timestep * self.surfaceArea * tempDiff
 
        #update the energy
        self.addEnergy(energyHeater + energyTransfer)

        # notice that energyTransfer can be negative return that so it can be
        #   used to either add or remove energy from the environment
        # Return the negation of calculated energy transfer
        return (-energyTransfer)

'''
Not smart yet, but what it does is poll the source for the temperature
and then cache it for later retrieval.
'''
class SmartThermometer (threading.Thread) :
    def __init__ (self, source, updatePeriod) :
        threading.Thread.__init__(self, daemon = True) 
        #set daemon to be true, so it doesn't block program from exiting
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()

    def setSource(self, source) :
        self.source = source

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod 

    def updateTemperature(self) :
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self) :
        return self.curTemperature

    def run(self) : #the running function
        while True :
            self.updateTemperature()
            time.sleep(self.updatePeriod)

'''
Not smart yet, but at least it runs as a thread
'''
class SmartHeater (threading.Thread) :
    def __init__ (self, powerOutput, setTemperature, thermometer, updatePeriod) :
        threading.Thread.__init__(self, daemon = True)
        self.power = powerOutput
        self.setTemperature = setTemperature 
        self.thermometer = thermometer
        self.updatePeriod = updatePeriod
        self.curOutput = 0

    def setThermometer(self, thermo) :
        self.thermometer = thermo

    def setUpdatePeriod(self, updatePeriod) :
        self.updatePeriod = updatePeriod

    ''' 
    Returns the number of Watts output by this heater for this timestep.
    '''
    def getOutput(self) :
        return self.curOutput

    def run(self) :
        while True :
            if self.thermometer :
                if self.thermometer.getTemperature() < self.setTemperature :
                    self.curOutput = self.power
                else :
                    self.curOutput = 0
            time.sleep(self.updatePeriod)

'''
This class represents the incubator / chamber
'''
class Incubator :

    DENSITY = 1.2041       # UNIT: kg / m**3
    SPECIFIC_HEAT = 1012   # UNIT: J / kg / degK
    THERMAL_TRANSFER = 5.1 # UNIT: J / s / m**2 / degK

    def __init__ (self, width, depth, height, temperature, roomTemperature) :
        self.width = width                          # UNIT: m
        self.depth = depth                          # UNIT: m
        self.height = height                        # UNIT: m
        self.incuHeater = None                      # UNIT: W = J / s
        self.temperature = temperature              # UNIT: degK
        self.roomTemperature = roomTemperature      # UNIT: degK

        self.volume = self.depth * self.width * self.height
                                                    # UNIT: m**3
        self.mass = Incubator.DENSITY * self.volume # UNIT: kg
        self.energy = self.calculateEnergy()        # UNIT: J

        self.surfaceArea = self.width * self.depth + 2 * self.width * self.height + 2 * self.width * self.depth

        self.infant = None

    def setHeater(self, ihg) :
        self.incuHeater = ihg

    def calculateEnergy(self) :
        # The energy content is calculated based on the current temperature    
        return (Incubator.SPECIFIC_HEAT * self.mass * self.temperature)

    def calculateTemperature(self) :
        # The temperature is based on the amount of energy
        return (self.energy / Incubator.SPECIFIC_HEAT / self.mass)

    def getEnergy(self) :
        return self.energy

    def getTemperature(self) :
        return self.temperature

    def addEnergy(self, e) :
        self.energy += e 
        #update the temperature
        self.temperature = self.calculateTemperature()

    def openIncubator(self) :
        #let's assume that when you open the incubator
        # the temperature settles half way to room temperature
        self.temperature += (self.roomTemperature - self.temperature) / 2
        #update energy
        self.energy = self.calculateEnergy()
   
    def addInfant(self, newInfant) :
        # Let's see if someone catches these
        self.infant = newInfant

        #First, lets calculate the displacement in volume so we can update energy
        airVolume = self.volume - self.infant.volume

        #now update the energy content based on the current temperature
        airMass = Incubator.DENSITY * airVolume
        energy = Incubator.SPECIFIC_HEAT * airMass * self.temperature
        
    def closeIncubator(self) :
        pass #nothing to do here for the simulation

    def hasInfant(self) :
        return not self.infant is None 

    def simulateTransferWithRoom(self, timestep, envTemp) :
        # envTemp is the temperature of the environment
        # so we will have to calculate the temperature difference first
        tempDiff = envTemp - self.temperature

        # then figure out how much energy was generated by heater
        if self.incuHeater :
            energyHeater = self.incuHeater.getOutput() * timestep # UNIT: J
        else :
            energyHeater = 0

        # then using temperature difference how much energy transferred
        energyTransfer = Incubator.THERMAL_TRANSFER * timestep * self.surfaceArea * tempDiff

        #update the energy
        self.addEnergy(energyHeater + energyTransfer)

        # notice that energyTransfer can be negative return that so it can be
        #   used to either add or remove energy from the environment
        # Return the negation of calculated energy transfer
        return (-energyTransfer)

class Simulator (threading.Thread) :
    
    def __init__ (self, infant, incubator, roomTemp, timeStep, sleepTime) : 
        #infWeight, infLength, infTemp, infant, incWidth, incDepth, incHeight, incTemp, roomTemp, timeStep) :

        threading.Thread.__init__(self, daemon = True)
        self.infant = infant #Human(infWeight, infLength, infTemp)
        self.incubator = incubator #Incubator(incWidth, incDepth, incHeight, incTemp, roomTemp)
        self.roomTemperature = roomTemp
        self.iteration = 0
        self.timeStep = timeStep
        self.sleepTime = sleepTime

    def run(self) :
        while True :
            #1. Simulate infant using incubator temperature
            e = self.infant.simulateTransferWithChamber(self.timeStep, self.incubator.getTemperature())
            #2. Infant is updated, now incubator with room
            e2 = self.incubator.simulateTransferWithRoom(self.timeStep, self.roomTemperature)
            #3. Add the energy gain or loss from infant
            self.incubator.addEnergy(e)
    
            time.sleep(self.sleepTime)

