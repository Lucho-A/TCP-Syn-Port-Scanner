################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Src/TCP_Syn_Port_Scanner_Minimal.c 

C_DEPS += \
./Src/TCP_Syn_Port_Scanner_Minimal.d 

OBJS += \
./Src/TCP_Syn_Port_Scanner_Minimal.o 


# Each subdirectory must supply rules for building sources it contributes
Src/%.o: ../Src/%.c Src/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I"/home/lucho/git/TCP-Syn-Port-Scanner-Minimal/TCP-Syn-Port-Scanner-Minimal/Src/Headers" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-Src

clean-Src:
	-$(RM) ./Src/TCP_Syn_Port_Scanner_Minimal.d ./Src/TCP_Syn_Port_Scanner_Minimal.o

.PHONY: clean-Src

