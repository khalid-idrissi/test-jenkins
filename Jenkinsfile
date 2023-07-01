pipeline {
    agent any
    environment {
		PARAM = credentials('netboxtoken')
		tokenpywire = credentials('tokenpywire')
		token = credentials('token')
    }
    stages {
        stage('Intsall Packages') {
            steps {
				echo "Intsall Packages"
				bat 'pip install requests'
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat "python jenkins.py ${PARAM} ${tokenpywire} ${token}"

            }
        }
    }
}