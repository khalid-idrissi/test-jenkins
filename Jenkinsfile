pipeline {
    agent any
    environment {
        PARAM1 = "value1"
        PARAM2 = "value2"
		PARAM3 = credentials('netboxtoken')
    }
    stages {
        stage('Intsall Packages') {
            steps {
				echo "Intsall Packages"
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "python importation_equipements/jenkins.py ${PARAM1} ${PARAM2} ${PARAM3}"

            }
        }
    }
}