################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Src/Modules/Common_functions.c \
../Src/Modules/Grabbing_cert.c \
../Src/Modules/Grabbing_port.c \
../Src/Modules/Hack_mysql.c \
../Src/Modules/Hack_web.c \
../Src/Modules/System_call.c 

C_DEPS += \
./Src/Modules/Common_functions.d \
./Src/Modules/Grabbing_cert.d \
./Src/Modules/Grabbing_port.d \
./Src/Modules/Hack_mysql.d \
./Src/Modules/Hack_web.d \
./Src/Modules/System_call.d 

OBJS += \
./Src/Modules/Common_functions.o \
./Src/Modules/Grabbing_cert.o \
./Src/Modules/Grabbing_port.o \
./Src/Modules/Hack_mysql.o \
./Src/Modules/Hack_web.o \
./Src/Modules/System_call.o 


# Each subdirectory must supply rules for building sources it contributes
Src/Modules/%.o: ../Src/Modules/%.c Src/Modules/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I"/home/lucho/git/TCP-Syn-Port-Scanner-Minimal/TCP-Syn-Port-Scanner-Minimal/Src/Headers" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-Src-2f-Modules

clean-Src-2f-Modules:
	-$(RM) ./Src/Modules/Common_functions.d ./Src/Modules/Common_functions.o ./Src/Modules/Grabbing_cert.d ./Src/Modules/Grabbing_cert.o ./Src/Modules/Grabbing_port.d ./Src/Modules/Grabbing_port.o ./Src/Modules/Hack_mysql.d ./Src/Modules/Hack_mysql.o ./Src/Modules/Hack_web.d ./Src/Modules/Hack_web.o ./Src/Modules/System_call.d ./Src/Modules/System_call.o

.PHONY: clean-Src-2f-Modules

